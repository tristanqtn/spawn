# What is tested, feature by feature

Every `Test*` function in the package appears below, grouped by the feature it covers.
`TestValidationMatrixIsComplete` fails if one is missing, so this file cannot quietly
fall behind the code — which is the only way a document like this is worth reading.

`go test -short ./...` runs the unit tests (seconds). `go test ./...` adds the
integration tests, which need rootless podman and a nix store and **skip** rather than
fail without them. The two scripted suites are listed at the end.

## Manifest and schema

| Test | Asserts |
|---|---|
| `TestParseRejects` | unknown fields, wrong schema version, missing name, attr injection |
| `TestParseResolves` | base tools merged, nixpkgs defaulted, expression shape |
| `TestDefaultNixpkgsIsPinnedToARevision` | the default pin is a 40-char revision, never a branch |
| `TestLicenceOptIns` | `allow_unfree` / `allow_insecure` reach the nix config, off by default |
| `TestProfilesMergeAndDedup` | several suites merge with no duplicates |
| `TestShippedProfilesAreValid` | every shipped suite parses and names valid attrs |
| `TestProfileNamesAreParseable` | `--names` output is what CI can consume |
| `TestWorkdirDefaultsAndValidates` | `/root` default, cleaned, relative rejected |

## Composable suites and smoke checks

| Test | Asserts |
|---|---|
| `TestProfileIncludesCompose` | a suite's includes really contribute, and it does not list them itself |
| `TestPentestComposesWithoutDuplicates` | the umbrella suite pulls in every block, and a diamond dedups |
| `TestProfileIncludeCycleTerminates` | an already-visited include is not expanded again |
| `TestProfileIncludeMustExist` | a missing suite errors; path separators refused |
| `TestEverySuiteToolHasASmokeCheck` | **the M5 criterion**: every tool in every suite is covered, by table or default |
| `TestNoSmokeEntryIsOrphaned` | no `[smoke]` key names a tool the suite does not install |
| `TestOuterSmokeEntryWins` | a composed suite inherits, and can override, a block's check |
| `TestSmokeDefaultsToTheAttrName` | the fallback is exactly `command -v <attr>` |
| `TestNotesSurviveComposition` | a suite's note reaches the composed suite; no profile grants caps |
| `TestSmokeManifestIsSealed` | a smoke env denies egress and holds NET_RAW |
| `TestOverlayOnlyWhenUsed` | a spawn-maintained package changes the expression only when resolved |
| `TestOverlayFragmentsAreWellFormed` | each `pkgs/*.nix` is a two-argument function |
| `TestHashcatOverrideIsPinned` | the hashcat override names a version and a hash, never a branch |
| `TestCISmokesEverySuite` | the CI smoke matrix and `spawn profiles --names` cannot drift apart |
| `TestOpenCLVendorsSetWithPocl` | `OCL_ICD_VENDORS` is set when pocl is present, absent otherwise |

## Runtime surface

| Test | Asserts |
|---|---|
| `TestRuntimeValidationRejects` | bad ports, caps, devices, mounts, env keys, limits |
| `TestRuntimeArgs` | podman flags rendered, env sorted, relative mounts made absolute |
| `TestMissingHostPathCaughtBeforeBuild` | a typo'd mount fails before the nix build, not after |

## Declared files and the generated shell

| Test | Asserts |
|---|---|
| `TestFilesValidationRejects` | relative paths, store paths, shadowed-by-mount, bad modes |
| `TestFileModeDefaultsAndParses` | 0644 default, octal round-trip |
| `TestWriteIfChanged` | identical content not rewritten, a mode change still applied |
| `TestCopyTreeKeepsExecutableBitAndSkipsSymlinks` | config trees copy correctly |
| `TestSeedBaseEtcProvidesIdentity` | `/etc/passwd` exists, login shell is the profile's |
| `TestShellValidationRejects` | unknown shell or prompt, unsafe alias names |
| `TestShellImpliesItsPackages` | `use = "zsh"` pulls in zsh; bash is the default |
| `TestShellHistoryAddsPersist` | history persists by default, opt-out works |
| `TestIntegrationsFollowThePackages` | fzf/zoxide/direnv wired only when present; highlighting last |
| `TestRCQuotesAliasesAndGuardsNonInteractive` | alias quoting, non-interactive guard, init last |
| `TestExegolPromptMatchesTheTemplate` | the built-in prompt and the template cannot drift |

## Secrets

| Test | Asserts |
|---|---|
| `TestParseSecretSpecs` | `age:`/`sops:`/`file:` forms, bad names rejected |
| `TestSecretReachesEnvButLeaksNowhere` | a real canary reaches the env and is absent from `/nix/store`, spawn's state and container metadata |

## Egress policy, VPN, kill switch

| Test | Asserts |
|---|---|
| `TestNetworkValidationRejects` | bad egress modes, allow entries, vpn kinds, dangling secret handles |
| `TestEffectiveEgress` | a declared VPN implies vpn-only; `kill_switch = false` opts out |
| `TestNetworkAddsItsPackagesAndPrivileges` | nftables/client added, caps and devices not duplicated |
| `TestNftRulesetVPNMode` | default-drop, tunnel allowed, endpoint pinned by IP, audit set present |
| `TestNftRulesetDenyMode` | default-drop with no tunnel referenced |
| `TestWireguardUsesItsOwnInterface` | `wg0`, never `tun0` |
| `TestParseEndpointsOpenVPN` | defaults, explicit proto, failover remotes, no-remote rejected |
| `TestParseEndpointsWireGuard` | `Endpoint` parsed, peerless and portless configs rejected |
| `TestParseEndpointsRejectsIPv6Only` | an IPv6-only endpoint errors rather than silently never matching |
| `TestNetupScriptAppliesPolicyBeforeConnecting` | policy precedes the tunnel; failures abort |
| `TestNetupScriptUsesNoUninstalledTools` | no sed/grep/pgrep/awk/cut/tr |
| `TestNetupScriptIsValidBash` | the generated script passes `bash -n` |
| `TestEgressPolicyBlocksAndPermits` | **the leak test**: deny blocks with the drop counter moving; an allow entry reaches and its neighbour does not |
| `TestKillSwitchHoldsWithNoTunnel` | an env whose tunnel never came up is sealed, not open |
| `TestAuditRecordsRefusedDestinations` | refused destinations recorded; allowed ones absent |
| `TestJoinedEnvsReachEachOther` | `network.join` gives direct env-to-env reachability |

## Lifecycle, snapshots, diffs, portability

| Test | Asserts |
|---|---|
| `TestEnvLifecycle` | reuse, restart with data, manifest change replaces the container and keeps the rootfs |
| `TestPersistSurvivesRmAndRebuild` | declared data survives `rm`; undeclared data does not |
| `TestHashTreeAndDiff` | added/modified/deleted; a freshly seeded env shows nothing; same-length edits caught |
| `TestDiffWithoutBaselineExplainsItself` | a missing baseline says what is missing |
| `TestCopyDirPreservesModesAndSymlinks` | 0600 preserved, symlinks not flattened |
| `TestSnapshotTagValidation` | path separators rejected, existing tags refused |
| `TestSnapshotRestoreForkAgainstARealEnv` | snapshot, change, restore, fork against a live env |
| `TestNthEnvFromOneProfileIsNearlyFree` | **the disk criterion**: 3,264 B against a 232 MB shared closure |
| `TestExportImportRoundTrip` | archive stays kilobytes, rename applied, work intact, overwrite refused |
| `TestSafeJoinRefusesEscapes` | archive members cannot escape the destination |
| `TestImportRefusesATraversalArchive` | a traversing member lands neither outside nor inside |
| `TestImportKeepsSymlinksWithoutFollowingThem` | links recreated, never resolved; `hashTree` does not walk out |
| `TestImportRefusesAnArchiveWithNoManifest` | nothing to rebuild from is an error |
| `TestImportRefusesAGarbageFile` | a non-archive is refused |

## The agent interface

| Test | Asserts |
|---|---|
| `TestMCPHandshake` | protocol version and the tools capability |
| `TestMCPNotificationsAreSilent` | notifications draw no response |
| `TestMCPToolsListIsWellFormed` | namespaced names, schemas, descriptions long enough to guide |
| `TestMCPUnknownMethodAndBadJSON` | protocol errors with the right codes |
| `TestMCPToolFailureIsAResult` | tool failure is `isError`, not a JSON-RPC error |
| `TestMCPUnknownToolIsRejected` | an invented tool name is an error result |
| `TestMCPToolCallLifecycle` | create/exec/diff/snapshot/restore/audit/list/destroy, and their failure paths |
| `TestAgentManifestDeniesEgressByDefault` | **deny by default**, nftables present, audit set present, allow list is the only way out |
| `TestAgentManifestTextParsesBack` | the manifest written for an agent parses back |

## Host diagnosis and dependencies

| Test | Asserts |
|---|---|
| `TestMissingDependencyIsActionable` | names the tool, how to install it, and `spawn doctor` |
| `TestCheckWithoutNixExplainsItself` | never an empty reason |
| `TestFsTypeOf` | longest-prefix mount matching, missing paths resolved |
| `TestUnusableRootfsFS` | drvfs/9p rejected, ext4/btrfs/xfs accepted |
| `TestShortRev` | 40-char revisions abbreviated, branch names left alone |
| `TestLimitField` | the cgroup controller maps to the manifest field name |

## CLI surface

| Test | Asserts |
|---|---|
| `TestResolveTargetPrecedence` | `.toml` beats env name beats default manifest |
| `TestManifestPathBeatsEnvName` | an explicit path is never read as a name |
| `TestEnvExistsRejectsNonNames` | no shelling out for something that cannot be a name |
| `TestAttachNeedsARecordedProfile` | attaching without a profile fails clearly |
| `TestAttachRunsWithoutTheManifest` | recorded shell used, attach starts a stopped env |
| `TestCompletionScripts` | each shell delegates to `__complete` and documents its install |
| `TestCompletionCandidates` | per-command candidates, including `--purge` and `--names` |
| `TestOnlyZshAsksForDescriptions` | bash and fish never receive descriptions |
| `TestCommandListsAgree` | help order and descriptions agree |
| `TestEveryDispatchedCommandIsDocumented` | `main()`'s switch matches help and completion both ways |
| `TestTemplateIsAWorkingManifest` | `spawn init`'s template parses and validates |
| `TestInitDoesNotOverwriteWithoutForce` | an edited dotfile survives a second `init` |
| `TestInitCreatesTheWorkspace` | the mount source exists after `init` |
| `TestTableAligns` | columns align, no trailing whitespace |
| `TestVisibleWidthIgnoresColour` | escape codes do not break alignment |
| `TestNoColourWhenNotATerminal` | piped output stays machine-readable |
| `TestTruncateKeepsTheTail` | a path's useful end is kept |
| `TestBannerHasNoEmoji` | ASCII only |

## Scripted suites

These need a second environment or a live agent loop, so they are scripts rather than
Go tests. Both run in CI.

| Script | Asserts |
|---|---|
| `test/vpn-datapath.sh` | a real payload crosses a real OpenVPN **and** WireGuard tunnel, with the kill switch sealing the non-tunnel interface |
| `test/agent-loop.py` | 17 assertions driving MCP as an agent would: provision, run a task, inspect the diff, read the audit log, snapshot, break, restore, destroy |
