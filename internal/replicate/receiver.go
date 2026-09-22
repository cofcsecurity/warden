package replicate

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path"
	"sort"
	"strings"
	"syscall"

	"warden/internal/manifest"
	"warden/internal/store"
)

const ReceiverCommand = "warden-receiver-v1"
const MaxReceiverBytes = 256 << 20

type Request struct {
	Operation  string
	Kind       string
	ID         string
	Tier       string
	Generation int
	Data       []byte `json:",omitempty"`
}
type Response struct {
	Data   []byte   `json:",omitempty"`
	Names  []string `json:",omitempty"`
	Exists bool
	Error  string `json:",omitempty"`
}

// Receiver has no delete, rename, shell, or retention operation. The root and
// verification key are selected by the administrator's forced SSH command.
type Receiver struct {
	Root      *os.Root
	PublicKey ed25519.PublicKey
	Source    string
}

func NewReceiver(root string, key ed25519.PublicKey, source string) (*Receiver, error) {
	r, err := os.OpenRoot(root)
	if err != nil {
		return nil, err
	}
	return &Receiver{Root: r, PublicKey: key, Source: source}, nil
}
func (r *Receiver) Close() error { return r.Root.Close() }
func (r *Receiver) Serve(in io.Reader, out io.Writer) error {
	var req Request
	dec := json.NewDecoder(io.LimitReader(in, MaxReceiverBytes+1))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&req); err != nil {
		return err
	}
	if err := dec.Decode(new(any)); err != io.EOF {
		return fmt.Errorf("expected one request")
	}
	result := r.Handle(req)
	return json.NewEncoder(out).Encode(result)
}
func validName(s string) bool {
	return s != "" && s != "." && s != ".." && len(s) <= 200 && !strings.ContainsAny(s, "/\\\x00\n\r")
}
func location(q Request) (dir, file string, err error) {
	switch q.Kind {
	case "object":
		dir = "objects"
		if q.Operation != "list" {
			if !store.ValidHash(q.ID) {
				return "", "", fmt.Errorf("invalid hash")
			}
			dir += "/" + q.ID[:2]
			file = q.ID
		}
	case "manifest":
		if q.Tier != "config" && q.Tier != "data" {
			return "", "", fmt.Errorf("invalid tier")
		}
		dir = "manifests-" + q.Tier
		if q.Operation != "list" {
			if q.Generation <= 0 {
				return "", "", fmt.Errorf("invalid generation")
			}
			file = fmt.Sprintf("manifest-%d.json", q.Generation)
		}
	case "audit", "heartbeat":
		dir = q.Kind
		if q.Operation != "list" {
			if !validName(q.ID) {
				return "", "", fmt.Errorf("invalid name")
			}
			file = q.ID
		}
	default:
		return "", "", fmt.Errorf("invalid kind")
	}
	return dir, file, nil
}
func (r *Receiver) Handle(q Request) (res Response) {
	err := r.handle(q, &res)
	if err != nil {
		res.Error = err.Error()
	}
	return
}
func (r *Receiver) handle(q Request, res *Response) error {
	if q.Operation != "get" && q.Operation != "has" && q.Operation != "put" && q.Operation != "list" {
		return fmt.Errorf("unsupported operation")
	}
	dir, file, err := location(q)
	if err != nil {
		return err
	}
	name := path.Join(dir, file)
	if q.Operation == "list" {
		f, err := r.Root.Open(dir)
		if os.IsNotExist(err) {
			return nil
		}
		if err != nil {
			return err
		}
		defer f.Close()
		entries, err := f.ReadDir(-1)
		if err != nil {
			return err
		}
		for _, e := range entries {
			if e.Type().IsRegular() && !strings.HasPrefix(e.Name(), ".pending-") {
				res.Names = append(res.Names, e.Name())
			}
		}
		sort.Strings(res.Names)
		return nil
	}
	if q.Operation == "get" || q.Operation == "has" {
		f, err := r.Root.OpenFile(name, os.O_RDONLY|syscall.O_NONBLOCK, 0)
		if os.IsNotExist(err) && q.Operation == "has" {
			return nil
		}
		if err != nil {
			return err
		}
		defer f.Close()
		info, err := f.Stat()
		if err != nil {
			return err
		}
		if !info.Mode().IsRegular() {
			return fmt.Errorf("not a regular file")
		}
		res.Exists = true
		if q.Operation == "get" {
			res.Data, err = io.ReadAll(io.LimitReader(f, MaxReceiverBytes+1))
			if len(res.Data) > MaxReceiverBytes {
				return fmt.Errorf("file exceeds receiver limit")
			}
			return err
		}
		return nil
	}
	if len(q.Data) > MaxReceiverBytes {
		return fmt.Errorf("payload too large")
	}
	if q.Kind == "object" {
		if err := store.Verify(q.ID, q.Data); err != nil {
			return err
		}
	}
	if q.Kind == "manifest" {
		m, err := manifest.Parse(q.Data)
		if err != nil {
			return err
		}
		if m.Generation != q.Generation {
			return fmt.Errorf("generation mismatch")
		}
		if len(r.PublicKey) > 0 {
			if err := m.Verify(r.PublicKey, r.Source, q.Tier); err != nil {
				return err
			}
		}
	}
	if err := r.Root.MkdirAll(dir, 0700); err != nil {
		return err
	}
	// Use an unguessable staging name and a no-replace link inside the confined root.
	nonce := make([]byte, 16)
	if _, err := rand.Read(nonce); err != nil {
		return err
	}
	tmp := path.Join(dir, ".pending-"+hex.EncodeToString(nonce))
	f, err := r.Root.OpenFile(tmp, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
	if err != nil {
		return err
	}
	defer r.Root.Remove(tmp)
	if _, err = f.Write(q.Data); err != nil {
		f.Close()
		return err
	}
	if err = f.Sync(); err != nil {
		f.Close()
		return err
	}
	if err = f.Close(); err != nil {
		return err
	}
	if err = r.Root.Link(tmp, name); err != nil {
		if !os.IsExist(err) {
			return err
		}
		existing := r.Handle(Request{Operation: "get", Kind: q.Kind, ID: q.ID, Tier: q.Tier, Generation: q.Generation})
		if existing.Error != "" {
			return fmt.Errorf("existing copy: %s", existing.Error)
		}
		if !bytes.Equal(existing.Data, q.Data) {
			return fmt.Errorf("conflicting existing copy")
		}
	}
	return nil
}

// ReceiverTarget uses the same pinned SSH transport but sends only protocol JSON.
type ReceiverTarget struct{ Transport *SSHTarget }

func (t *ReceiverTarget) request(q Request) (Response, error) {
	session, err := t.Transport.newSession()
	if err != nil {
		return Response{}, err
	}
	defer session.Close()
	data, err := json.Marshal(q)
	if err != nil {
		return Response{}, err
	}
	session.Stdin = bytes.NewReader(data)
	var out bytes.Buffer
	session.Stdout = &out
	if err := t.Transport.runSession(session, ReceiverCommand); err != nil {
		return Response{}, err
	}
	var res Response
	if err := json.Unmarshal(out.Bytes(), &res); err != nil {
		return res, err
	}
	if res.Error != "" {
		return res, fmt.Errorf("receiver: %s", res.Error)
	}
	return res, nil
}
func (t *ReceiverTarget) Has(h string) (bool, error) {
	r, e := t.request(Request{Operation: "has", Kind: "object", ID: h})
	return r.Exists, e
}
func (t *ReceiverTarget) Get(h string) ([]byte, error) {
	r, e := t.request(Request{Operation: "get", Kind: "object", ID: h})
	return r.Data, e
}
func (t *ReceiverTarget) Put(h string, b []byte) error {
	_, e := t.request(Request{Operation: "put", Kind: "object", ID: h, Data: b})
	return e
}
func (t *ReceiverTarget) HasManifest(ns string, g int) (bool, error) {
	r, e := t.request(Request{Operation: "has", Kind: "manifest", Tier: ns, Generation: g})
	return r.Exists, e
}
func (t *ReceiverTarget) GetManifest(ns string, g int) ([]byte, error) {
	r, e := t.request(Request{Operation: "get", Kind: "manifest", Tier: ns, Generation: g})
	return r.Data, e
}
func (t *ReceiverTarget) PutManifest(ns string, g int, b []byte) error {
	_, e := t.request(Request{Operation: "put", Kind: "manifest", Tier: ns, Generation: g, Data: b})
	return e
}
func (t *ReceiverTarget) ManifestGenerations(ns string) ([]int, error) {
	r, e := t.request(Request{Operation: "list", Kind: "manifest", Tier: ns})
	var out []int
	for _, name := range r.Names {
		var g int
		if _, err := fmt.Sscanf(name, "manifest-%d.json", &g); err == nil && g > 0 && name == fmt.Sprintf("manifest-%d.json", g) {
			out = append(out, g)
		}
	}
	sort.Ints(out)
	return out, e
}
func (t *ReceiverTarget) HasAudit(n string) (bool, error) {
	r, e := t.request(Request{Operation: "has", Kind: "audit", ID: n})
	return r.Exists, e
}
func (t *ReceiverTarget) GetAudit(n string) ([]byte, error) {
	r, e := t.request(Request{Operation: "get", Kind: "audit", ID: n})
	return r.Data, e
}
func (t *ReceiverTarget) PutAudit(n string, b []byte) error {
	_, e := t.request(Request{Operation: "put", Kind: "audit", ID: n, Data: b})
	return e
}
func (t *ReceiverTarget) AuditSegments() ([]string, error) {
	r, e := t.request(Request{Operation: "list", Kind: "audit"})
	return r.Names, e
}
func (t *ReceiverTarget) PutHeartbeat(n string, b []byte) error {
	_, e := t.request(Request{Operation: "put", Kind: "heartbeat", ID: n, Data: b})
	return e
}
