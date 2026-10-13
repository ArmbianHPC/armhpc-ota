# Upgrade to 1.1.0

Use the Windows MSI or extract the Linux controller archive. Authenticate each device, then select the signed maintenance package to update its OTA tools. Push the matching system OTA archive to update the normal system and Rescue. The device manages verification, persistent tasks and reboot recovery.

If a locally numbered Windows installer higher than 1.1.0 is already installed, close its controller and uninstall that application before installing this MSI. Its AppData profile and device-side tasks are retained. Do not delete the profile to work around installer version ordering.

Existing system baselines and protocol identifiers are retained. Use the original task IDs when reconnecting or continuing an operation.
