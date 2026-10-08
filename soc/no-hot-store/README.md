Intentionally empty. Mounted read-only into the Talon API when `SOC_HOT_DIR`
isn't set (e.g. prod before SOC Phase 1 is released), so the Events view shows
"not connected" instead of Docker creating a root-owned folder somewhere.
