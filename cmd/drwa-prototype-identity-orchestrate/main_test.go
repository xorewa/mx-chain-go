package main

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"runtime"
	"sort"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/multiversx/mx-chain-core-go/data/block"
	"github.com/multiversx/mx-chain-core-go/marshal"
	"github.com/multiversx/mx-chain-go/process/smartContract/drwaprototype/networkidentity"
	"github.com/stretchr/testify/require"
	"github.com/syndtr/goleveldb/leveldb"
)

func TestValidateContractRejectsEveryBoundaryMutation(t *testing.T) {
	fixture := newOrchestrationFixture(t)
	require.NoError(t, validateContract(fixture.contract))

	mutations := map[string]func(*orchestrationContract){
		"schema":                 func(value *orchestrationContract) { value.Schema = "wrong" },
		"status":                 func(value *orchestrationContract) { value.Status = "wrong" },
		"runtime credit":         func(value *orchestrationContract) { value.AuthoritativeRuntimeCredit = 1 },
		"host namespace":         func(value *orchestrationContract) { value.HostNetworkNamespace = "" },
		"provenance":             func(value *orchestrationContract) { value.IdentityProvenance = "LOCAL_CANONICAL_GENESIS" },
		"non-UTC timestamp":      func(value *orchestrationContract) { value.CreatedUTC = "2026-08-26T01:00:00+01:00" },
		"noncanonical timestamp": func(value *orchestrationContract) { value.CreatedUTC = "2026-08-26T00:00:00.000Z" },
		"short health timeout":   func(value *orchestrationContract) { value.HealthTimeoutSeconds = 29 },
		"long health timeout":    func(value *orchestrationContract) { value.HealthTimeoutSeconds = 601 },
		"short shutdown timeout": func(value *orchestrationContract) { value.ShutdownTimeoutSeconds = 9 },
		"long shutdown timeout":  func(value *orchestrationContract) { value.ShutdownTimeoutSeconds = 121 },
		"bad canonical hash":     func(value *orchestrationContract) { value.CanonicalMetachainHash = "ABC" },
		"wrong container image":  func(value *orchestrationContract) { value.ContainerRuntime.ImageID = "latest" },
		"wrong container repo digest": func(value *orchestrationContract) {
			value.ContainerRuntime.ImageRepoDigest = "latest"
		},
		"wrong container platform": func(value *orchestrationContract) { value.ContainerRuntime.Platform = "linux/arm64" },
		"missing container name":   func(value *orchestrationContract) { value.ContainerRuntime.Name = "" },
		"wrong container hostname": func(value *orchestrationContract) { value.ContainerRuntime.Hostname += "-other" },
		"wrong container user":     func(value *orchestrationContract) { value.ContainerRuntime.UID = 0 },
		"wrong container group":    func(value *orchestrationContract) { value.ContainerRuntime.GID = 0 },
		"wrong container network": func(value *orchestrationContract) {
			value.ContainerRuntime.NetworkMode = "host"
		},
		"wrong container pid mode":       func(value *orchestrationContract) { value.ContainerRuntime.PIDMode = "host" },
		"wrong container restart policy": func(value *orchestrationContract) { value.ContainerRuntime.RestartPolicy = "always" },
		"wrong container pull policy":    func(value *orchestrationContract) { value.ContainerRuntime.PullPolicy = "always" },
		"mutable container root":         func(value *orchestrationContract) { value.ContainerRuntime.ReadOnlyRootFS = false },
		"container auto remove":          func(value *orchestrationContract) { value.ContainerRuntime.AutoRemove = true },
		"outside orchestrator": func(value *orchestrationContract) {
			value.ContainerRuntime.Orchestrator.Path = filepath.Join(filepath.Dir(value.RehearsalRoot), "orchestrator")
		},
		"wrong orchestrator hash": func(value *orchestrationContract) {
			value.ContainerRuntime.Orchestrator.SHA256 = strings.Repeat("0", 63)
		},
		"container env drift": func(value *orchestrationContract) {
			value.ContainerRuntime.Environment = append(value.ContainerRuntime.Environment, "EXTRA=1")
		},
		"missing plan": func(value *orchestrationContract) { value.MigrationPlan.Path = "" },
		"missing writer contract": func(value *orchestrationContract) {
			value.WriterIsolationContract.Path = ""
		},
		"missing writer binary": func(value *orchestrationContract) { value.WriterBinary.Path = "" },
		"missing writer identity tool": func(value *orchestrationContract) {
			value.WriterIdentityTool.Path = ""
		},
		"missing writer stopped preflight": func(value *orchestrationContract) {
			value.WriterStoppedPreflight.Path = ""
		},
		"missing writer events": func(value *orchestrationContract) { value.WriterContainerEvents.Path = "" },
		"outside writer events": func(value *orchestrationContract) {
			value.WriterContainerEvents.Path = filepath.Join(filepath.Dir(value.RehearsalRoot), "events.jsonl")
		},
		"missing writer state": func(value *orchestrationContract) { value.WriterPostRunState.Path = "" },
		"missing writer logs":  func(value *orchestrationContract) { value.WriterLogsEvidence.Path = "" },
		"bad node digest":      func(value *orchestrationContract) { value.NodeBinary.SHA256 = strings.Repeat("0", 63) },
		"missing seccomp":      func(value *orchestrationContract) { value.SeccompProfile.Path = "" },
		"outside evidence": func(value *orchestrationContract) {
			value.EvidencePath = filepath.Join(filepath.Dir(value.RehearsalRoot), "escape.json")
		},
		"same outputs":             func(value *orchestrationContract) { value.EvidencePath = value.JournalPath },
		"outside node base":        func(value *orchestrationContract) { value.NodeBase = filepath.Dir(value.RehearsalRoot) },
		"outside seed root":        func(value *orchestrationContract) { value.SeedRoot = filepath.Dir(value.RehearsalRoot) },
		"empty collection":         func(value *orchestrationContract) { value.NodeBaseFiles = nil },
		"empty runtime collection": func(value *orchestrationContract) { value.RuntimeLibraries = nil },
		"inherited child environment": func(value *orchestrationContract) {
			value.ChildEnvironment = append(value.ChildEnvironment, "UNBOUND=value")
		},
		"missing read-only mount": func(value *orchestrationContract) {
			value.ReadOnlyMounts = value.ReadOnlyMounts[:3]
		},
		"extra read-only mount": func(value *orchestrationContract) {
			value.ReadOnlyMounts = append(value.ReadOnlyMounts, value.RehearsalRoot)
		},
		"wrong read-only mount": func(value *orchestrationContract) {
			value.ReadOnlyMounts[0] = value.RehearsalRoot
		},
		"outside collection": func(value *orchestrationContract) { value.NodeBaseFiles[0].Path = value.MigrationPlan.Path },
		"duplicate collection": func(value *orchestrationContract) {
			value.NodeBaseFiles = append(value.NodeBaseFiles, value.NodeBaseFiles[0])
		},
	}
	for name, mutate := range mutations {
		t.Run(name, func(t *testing.T) {
			changed := cloneContract(t, fixture.contract)
			mutate(&changed)
			require.Error(t, validateContract(changed))
		})
	}
}

func TestVerifyWriterArtifactBindingsReadsEveryExactArtifact(t *testing.T) {
	require.NoError(t, verifyWriterArtifactBindings(newOrchestrationFixture(t).contract))
	mutations := map[string]func(*orchestrationContract){
		"isolation contract": func(value *orchestrationContract) { value.WriterIsolationContract.SHA256 = strings.Repeat("0", 64) },
		"writer binary":      func(value *orchestrationContract) { value.WriterBinary.SHA256 = strings.Repeat("0", 64) },
		"identity tool":      func(value *orchestrationContract) { value.WriterIdentityTool.SHA256 = strings.Repeat("0", 64) },
		"stopped preflight":  func(value *orchestrationContract) { value.WriterStoppedPreflight.SHA256 = strings.Repeat("0", 64) },
		"container events":   func(value *orchestrationContract) { value.WriterContainerEvents.SHA256 = strings.Repeat("0", 64) },
		"post-run state":     func(value *orchestrationContract) { value.WriterPostRunState.SHA256 = strings.Repeat("0", 64) },
		"logs evidence":      func(value *orchestrationContract) { value.WriterLogsEvidence.SHA256 = strings.Repeat("0", 64) },
	}
	for name, mutate := range mutations {
		t.Run(name, func(t *testing.T) {
			fixture := newOrchestrationFixture(t)
			mutate(&fixture.contract)
			require.Error(t, verifyWriterArtifactBindings(fixture.contract))
		})
	}
}

func TestExactArtifactTreeRejectsEveryDriftClass(t *testing.T) {
	for _, test := range []struct {
		name   string
		mutate func(*testing.T, orchestrationFixture)
	}{
		{name: "extra file", mutate: func(t *testing.T, fixture orchestrationFixture) {
			require.NoError(t, os.WriteFile(filepath.Join(fixture.contract.NodeBase, "extra"), []byte("x"), 0o600))
		}},
		{name: "changed bytes", mutate: func(t *testing.T, fixture orchestrationFixture) {
			require.NoError(t, os.WriteFile(fixture.contract.NodeBaseFiles[0].Path, []byte("changed"), 0o600))
		}},
		{name: "missing file", mutate: func(t *testing.T, fixture orchestrationFixture) {
			require.NoError(t, os.Remove(fixture.contract.NodeBaseFiles[0].Path))
		}},
		{name: "symlink", mutate: func(t *testing.T, fixture orchestrationFixture) {
			target := filepath.Join(fixture.root, "target")
			require.NoError(t, os.WriteFile(target, []byte("target"), 0o600))
			require.NoError(t, os.Symlink(target, filepath.Join(fixture.contract.NodeBase, "link")))
		}},
		{name: "extra empty directory", mutate: func(t *testing.T, fixture orchestrationFixture) {
			require.NoError(t, os.Mkdir(filepath.Join(fixture.contract.NodeBase, "unbound"), 0o700))
		}},
		{name: "extra nested directory", mutate: func(t *testing.T, fixture orchestrationFixture) {
			require.NoError(t, os.MkdirAll(filepath.Join(fixture.contract.NodeBase, "unbound", "nested"), 0o700))
		}},
	} {
		t.Run(test.name, func(t *testing.T) {
			fixture := newOrchestrationFixture(t)
			require.NoError(t, verifyArtifactCollections(fixture.contract))
			test.mutate(t, fixture)
			require.Error(t, verifyArtifactCollections(fixture.contract))
		})
	}
}

func TestExactArtifactTreeAllowsOnlyDirectoriesRequiredByBoundFiles(t *testing.T) {
	fixture := newOrchestrationFixture(t)
	nested := filepath.Join(fixture.contract.NodeBase, "config", "nested")
	require.NoError(t, os.MkdirAll(nested, 0o700))
	fixture.contract.NodeBaseFiles = append(
		fixture.contract.NodeBaseFiles,
		writeArtifact(t, filepath.Join(nested, "bound.toml"), []byte("bound")),
	)

	require.NoError(t, verifyArtifactCollections(fixture.contract))
	require.NoError(t, os.Mkdir(filepath.Join(nested, "unbound"), 0o700))
	require.ErrorContains(t, verifyArtifactCollections(fixture.contract), "unbound directory")
}

func TestRuntimeLibraryCollectionIsVerifiedByTheProductionArtifactGate(t *testing.T) {
	for _, test := range []struct {
		name   string
		mutate func(*testing.T, orchestrationFixture)
	}{
		{name: "changed", mutate: func(t *testing.T, fixture orchestrationFixture) {
			require.NoError(t, os.WriteFile(fixture.contract.RuntimeLibraries[0].Path, []byte("changed"), 0o600))
		}},
		{name: "missing", mutate: func(t *testing.T, fixture orchestrationFixture) {
			require.NoError(t, os.Remove(fixture.contract.RuntimeLibraries[0].Path))
		}},
		{name: "extra", mutate: func(t *testing.T, fixture orchestrationFixture) {
			require.NoError(t, os.WriteFile(filepath.Join(fixture.contract.RuntimeLibraryDirectory, "extra.so"), []byte("x"), 0o600))
		}},
		{name: "symlink", mutate: func(t *testing.T, fixture orchestrationFixture) {
			require.NoError(t, os.Symlink(fixture.contract.RuntimeLibraries[0].Path, filepath.Join(fixture.contract.RuntimeLibraryDirectory, "link.so")))
		}},
	} {
		t.Run(test.name, func(t *testing.T) {
			fixture := newOrchestrationFixture(t)
			require.NoError(t, verifyArtifactCollections(fixture.contract))
			test.mutate(t, fixture)
			require.Error(t, verifyArtifactCollections(fixture.contract))
		})
	}
}

func TestIsolationStatusRequiresEveryZeroCapabilityMask(t *testing.T) {
	base := map[string]string{
		"NoNewPrivs": "1", "Seccomp": "2", "Seccomp_filters": "1", "CapInh": "0000000000000000",
		"CapPrm": "0000000000000000", "CapEff": "0000000000000000",
		"CapBnd": "0000000000000000", "CapAmb": "0000000000000000",
	}
	require.NoError(t, validateIsolationStatus(base))
	for _, field := range []string{"CapInh", "CapPrm", "CapEff", "CapBnd", "CapAmb"} {
		t.Run(field, func(t *testing.T) {
			changed := cloneStrings(base)
			changed[field] = "0000000000000001"
			require.ErrorContains(t, validateIsolationStatus(changed), field)
		})
	}
	for _, field := range []string{"NoNewPrivs", "Seccomp", "Seccomp_filters"} {
		t.Run(field, func(t *testing.T) {
			changed := cloneStrings(base)
			changed[field] = "0"
			require.Error(t, validateIsolationStatus(changed))
		})
	}
}

func TestRuntimeMountValidationDetectsEveryRequiredMountRemoval(t *testing.T) {
	fixture := newOrchestrationFixture(t)
	lines := []string{"1 0 0:1 / / ro - tmpfs tmpfs ro", "2 1 0:2 / " + fixture.root + " rw - bind bind rw"}
	for index, path := range fixture.contract.ReadOnlyMounts {
		lines = append(lines, fmt.Sprintf("%d 2 0:%d / %s ro - bind bind ro", index+3, index+3, strings.ReplaceAll(path, " ", `\040`)))
	}
	require.NoError(t, validateRuntimeMounts(strings.Join(lines, "\n"), fixture.contract))
	for index := range fixture.contract.ReadOnlyMounts {
		changed := append([]string(nil), lines...)
		changed = append(changed[:index+2], changed[index+3:]...)
		require.ErrorContains(t, validateRuntimeMounts(strings.Join(changed, "\n"), fixture.contract), "required exact read-only mount missing")
	}
	changed := append([]string(nil), lines...)
	changed[2] = strings.Replace(changed[2], " ro -", " rw -", 1)
	require.Error(t, validateRuntimeMounts(strings.Join(changed, "\n"), fixture.contract))
	extra := append(append([]string(nil), lines...), "99 2 0:99 / "+filepath.Join(fixture.root, "unexpected")+" ro - bind bind ro")
	require.ErrorContains(t, validateRuntimeMounts(strings.Join(extra, "\n"), fixture.contract), "unexpected nested rehearsal mount")
}

func TestChildRuntimeDirectoriesMustBeExactEmptyPrestate(t *testing.T) {
	for _, relative := range []string{"runtime/home", "runtime/tmp"} {
		t.Run(relative, func(t *testing.T) {
			fixture := newOrchestrationFixture(t)
			require.NoError(t, validateContract(fixture.contract))
			require.NoError(t, os.WriteFile(filepath.Join(fixture.root, relative, "unexpected"), []byte("x"), 0o600))
			require.ErrorContains(t, validateContract(fixture.contract), "exact empty prestate")
		})
	}
}

func TestStoppedContainerInspectionRejectsEverySubstrateDriftClass(t *testing.T) {
	fixture := newOrchestrationFixture(t)
	contractSHA := strings.Repeat("c", 64)
	container, image := exactDockerInspection(t, fixture.contract, contractSHA)
	require.NoError(t, validateStoppedContainerInspection(container, image, fixture.contract, filepath.Join(fixture.root, "artifacts", "contract.json"), contractSHA))
	mutations := map[string]func(*dockerContainerInspection, *dockerImageInspection){
		"running":       func(value *dockerContainerInspection, _ *dockerImageInspection) { value.State.Running = true },
		"status":        func(value *dockerContainerInspection, _ *dockerImageInspection) { value.State.Status = "exited" },
		"state pid":     func(value *dockerContainerInspection, _ *dockerImageInspection) { value.State.PID = 1 },
		"restart count": func(value *dockerContainerInspection, _ *dockerImageInspection) { value.RestartCount = 1 },
		"image": func(value *dockerContainerInspection, _ *dockerImageInspection) {
			value.Image = "sha256:" + strings.Repeat("0", 64)
		},
		"platform": func(value *dockerContainerInspection, _ *dockerImageInspection) { value.Platform = "linux/arm64" },
		"hostname": func(value *dockerContainerInspection, _ *dockerImageInspection) { value.Config.Hostname += "-other" },
		"user":     func(value *dockerContainerInspection, _ *dockerImageInspection) { value.Config.User = "0:0" },
		"entrypoint": func(value *dockerContainerInspection, _ *dockerImageInspection) {
			value.Config.Entrypoint = []string{"/bin/sh"}
		},
		"healthcheck": func(value *dockerContainerInspection, _ *dockerImageInspection) {
			value.Config.Healthcheck = json.RawMessage(`{}`)
		},
		"argv": func(value *dockerContainerInspection, _ *dockerImageInspection) {
			value.Config.Cmd[len(value.Config.Cmd)-1] = strings.Repeat("0", 64)
		},
		"network": func(value *dockerContainerInspection, _ *dockerImageInspection) {
			value.HostConfig.NetworkMode = "host"
		},
		"pid mode": func(value *dockerContainerInspection, _ *dockerImageInspection) { value.HostConfig.PIDMode = "host" },
		"restart": func(value *dockerContainerInspection, _ *dockerImageInspection) {
			value.HostConfig.RestartPolicy.Name = "always"
		},
		"auto remove": func(value *dockerContainerInspection, _ *dockerImageInspection) { value.HostConfig.AutoRemove = true },
		"writable root": func(value *dockerContainerInspection, _ *dockerImageInspection) {
			value.HostConfig.ReadonlyRootfs = false
		},
		"capability": func(value *dockerContainerInspection, _ *dockerImageInspection) { value.HostConfig.CapDrop = nil },
		"cap add": func(value *dockerContainerInspection, _ *dockerImageInspection) {
			value.HostConfig.CapAdd = []string{"SYS_ADMIN"}
		},
		"device": func(value *dockerContainerInspection, _ *dockerImageInspection) {
			value.HostConfig.Devices = []json.RawMessage{json.RawMessage(`{}`)}
		},
		"device request": func(value *dockerContainerInspection, _ *dockerImageInspection) {
			value.HostConfig.DeviceRequests = []json.RawMessage{json.RawMessage(`{}`)}
		},
		"device rule": func(value *dockerContainerInspection, _ *dockerImageInspection) {
			value.HostConfig.DeviceCgroupRules = []string{"c 1:3 rwm"}
		},
		"host ipc":    func(value *dockerContainerInspection, _ *dockerImageInspection) { value.HostConfig.IPCMode = "host" },
		"host uts":    func(value *dockerContainerInspection, _ *dockerImageInspection) { value.HostConfig.UTSMode = "host" },
		"host userns": func(value *dockerContainerInspection, _ *dockerImageInspection) { value.HostConfig.UsernsMode = "host" },
		"host cgroupns": func(value *dockerContainerInspection, _ *dockerImageInspection) {
			value.HostConfig.CgroupnsMode = "host"
		},
		"alternate runtime": func(value *dockerContainerInspection, _ *dockerImageInspection) { value.HostConfig.Runtime = "other" },
		"init process": func(value *dockerContainerInspection, _ *dockerImageInspection) {
			enabled := true
			value.HostConfig.Init = &enabled
		},
		"privileged": func(value *dockerContainerInspection, _ *dockerImageInspection) { value.HostConfig.Privileged = true },
		"published ports": func(value *dockerContainerInspection, _ *dockerImageInspection) {
			value.HostConfig.PublishAllPorts = true
		},
		"port binding": func(value *dockerContainerInspection, _ *dockerImageInspection) {
			value.HostConfig.PortBindings["80/tcp"] = struct{}{}
		},
		"seccomp": func(value *dockerContainerInspection, _ *dockerImageInspection) {
			value.HostConfig.SecurityOpt = []string{"no-new-privileges"}
		},
		"extra bind": func(value *dockerContainerInspection, _ *dockerImageInspection) {
			value.HostConfig.Binds = append(value.HostConfig.Binds, "/tmp:/tmp:ro")
		},
		"missing resolved mount": func(value *dockerContainerInspection, _ *dockerImageInspection) {
			value.Mounts = value.Mounts[:len(value.Mounts)-1]
		},
		"image ID": func(_ *dockerContainerInspection, value *dockerImageInspection) {
			value.ID = "sha256:" + strings.Repeat("0", 64)
		},
		"repo digest": func(_ *dockerContainerInspection, value *dockerImageInspection) { value.RepoDigests = nil },
		"image os":    func(_ *dockerContainerInspection, value *dockerImageInspection) { value.OS = "windows" },
		"image arch":  func(_ *dockerContainerInspection, value *dockerImageInspection) { value.Architecture = "arm64" },
	}
	for name, mutate := range mutations {
		t.Run(name, func(t *testing.T) {
			changedContainer, changedImage := exactDockerInspection(t, fixture.contract, contractSHA)
			mutate(&changedContainer, &changedImage)
			require.Error(t, validateStoppedContainerInspection(changedContainer, changedImage, fixture.contract, filepath.Join(fixture.root, "artifacts", "contract.json"), contractSHA))
		})
	}
}

func TestRuntimeSelfSnapshotRejectsEveryIdentityDriftClass(t *testing.T) {
	fixture := newOrchestrationFixture(t)
	contractPath := filepath.Join(fixture.root, "artifacts", "contract.json")
	contractSHA := strings.Repeat("c", 64)
	exact := runtimeSelfSnapshot{
		UID: fixture.contract.ContainerRuntime.UID, GID: fixture.contract.ContainerRuntime.GID,
		Hostname: fixture.contract.ContainerRuntime.Hostname, SelfSHA: fixture.contract.ContainerRuntime.Orchestrator.SHA256,
		Args: expectedRuntimeArgs(fixture.contract, contractPath, contractSHA),
		Env:  append([]string(nil), fixture.contract.ContainerRuntime.Environment...),
	}
	require.NoError(t, validateRuntimeSelfSnapshot(exact, fixture.contract, contractPath, contractSHA))
	mutations := map[string]func(*runtimeSelfSnapshot){
		"uid":      func(value *runtimeSelfSnapshot) { value.UID++ },
		"gid":      func(value *runtimeSelfSnapshot) { value.GID++ },
		"hostname": func(value *runtimeSelfSnapshot) { value.Hostname += "-other" },
		"self sha": func(value *runtimeSelfSnapshot) { value.SelfSHA = strings.Repeat("0", 64) },
		"argv":     func(value *runtimeSelfSnapshot) { value.Args[len(value.Args)-1] = strings.Repeat("0", 64) },
		"env":      func(value *runtimeSelfSnapshot) { value.Env = append(value.Env, "EXTRA=1") },
	}
	for name, mutate := range mutations {
		t.Run(name, func(t *testing.T) {
			changed := exact
			changed.Args = append([]string(nil), exact.Args...)
			changed.Env = append([]string(nil), exact.Env...)
			mutate(&changed)
			require.Error(t, validateRuntimeSelfSnapshot(changed, fixture.contract, contractPath, contractSHA))
		})
	}
}

func TestHostPreflightSelfIdentityRequiresExactSameBinary(t *testing.T) {
	fixture := newOrchestrationFixture(t)
	artifact := fixture.contract.ContainerRuntime.Orchestrator
	require.NoError(t, validateHostPreflightSelfIdentity(artifact.Path, artifact.SHA256, fixture.contract))
	require.Error(t, validateHostPreflightSelfIdentity(artifact.Path+".other", artifact.SHA256, fixture.contract))
	require.Error(t, validateHostPreflightSelfIdentity(artifact.Path, strings.Repeat("0", 64), fixture.contract))
}

func TestContainerPreflightEvidenceConsumerRejectsEveryBindingDrift(t *testing.T) {
	mutations := map[string]func(*containerPreflightEvidence){
		"schema":        func(value *containerPreflightEvidence) { value.Schema = "wrong" },
		"contract hash": func(value *containerPreflightEvidence) { value.ContractSHA256 = strings.Repeat("0", 64) },
		"container":     func(value *containerPreflightEvidence) { value.ContainerName += "-other" },
		"image":         func(value *containerPreflightEvidence) { value.ImageID = "sha256:" + strings.Repeat("0", 64) },
		"repo": func(value *containerPreflightEvidence) {
			value.ImageRepoDigest = "other@sha256:" + strings.Repeat("0", 64)
		},
		"platform": func(value *containerPreflightEvidence) { value.Platform = "linux/arm64" },
		"seccomp":  func(value *containerPreflightEvidence) { value.SeccompProfileSHA256 = strings.Repeat("0", 64) },
		"bind":     func(value *containerPreflightEvidence) { value.ExactBinds = value.ExactBinds[:len(value.ExactBinds)-1] },
		"raw path": func(value *containerPreflightEvidence) { value.ContainerInspectPath += ".other" },
		"raw hash": func(value *containerPreflightEvidence) { value.ContainerInspectSHA256 = strings.Repeat("0", 64) },
		"credit":   func(value *containerPreflightEvidence) { value.AuthoritativeCredit = 1 },
	}
	for name, mutate := range mutations {
		t.Run(name, func(t *testing.T) {
			fixture := newOrchestrationFixture(t)
			contractPath := filepath.Join(fixture.root, "artifacts", "contract.json")
			contractSHA := strings.Repeat("c", 64)
			evidence := exactContainerPreflightEvidence(fixture.contract, contractPath, contractSHA)
			materializeContainerPreflightRawFiles(t, fixture.contract, contractPath, contractSHA, &evidence)
			if name != "control" {
				mutate(&evidence)
			}
			encoded, err := json.Marshal(evidence)
			require.NoError(t, err)
			writeArtifact(t, fixture.contract.ContainerPreflightPath, encoded)
			_, err = verifyContainerPreflightEvidence(fixture.contract, contractPath, contractSHA)
			require.Error(t, err)
		})
	}
	fixture := newOrchestrationFixture(t)
	contractPath := filepath.Join(fixture.root, "artifacts", "contract.json")
	contractSHA := strings.Repeat("c", 64)
	evidence := exactContainerPreflightEvidence(fixture.contract, contractPath, contractSHA)
	materializeContainerPreflightRawFiles(t, fixture.contract, contractPath, contractSHA, &evidence)
	encoded, err := json.Marshal(evidence)
	require.NoError(t, err)
	writeArtifact(t, fixture.contract.ContainerPreflightPath, encoded)
	observedSHA, err := verifyContainerPreflightEvidence(fixture.contract, contractPath, contractSHA)
	require.NoError(t, err)
	require.Len(t, observedSHA, 64)
}

func exactContainerPreflightEvidence(contract orchestrationContract, contractPath, contractSHA string) containerPreflightEvidence {
	containerInspectPath, imageInspectPath := derivedRawInspectPaths(contract.ContainerPreflightPath)
	return containerPreflightEvidence{
		Schema:       "drwa.s1.prototype-network-identity-stopped-container-preflight.v1",
		Status:       "EXACT_STOPPED_CONTAINER_SUBSTRATE_VERIFIED_NO_PROCESS_NO_RUNTIME_CREDIT",
		TimestampUTC: "2026-08-26T00:00:00Z", ContractPath: contractPath, ContractSHA256: contractSHA,
		ContainerName: contract.ContainerRuntime.Name, ContainerID: strings.Repeat("d", 64),
		ContainerInspectPath: containerInspectPath, ImageInspectPath: imageInspectPath,
		ImageID: contract.ContainerRuntime.ImageID, ImageRepoDigest: contract.ContainerRuntime.ImageRepoDigest,
		Platform: contract.ContainerRuntime.Platform, ExactBinds: expectedContainerBinds(contract),
		SeccompProfilePath: contract.SeccompProfile.Path, SeccompProfileSHA256: contract.SeccompProfile.SHA256,
	}
}

func TestContainerPreflightConsumerRevalidatesRetainedRawSemantics(t *testing.T) {
	for _, name := range []string{"malformed", "privileged", "id-mismatch"} {
		t.Run(name, func(t *testing.T) {
			fixture := newOrchestrationFixture(t)
			contractPath := filepath.Join(fixture.root, "artifacts", "contract.json")
			contractSHA := strings.Repeat("c", 64)
			evidence := exactContainerPreflightEvidence(fixture.contract, contractPath, contractSHA)
			container, image := exactDockerInspection(t, fixture.contract, contractSHA)
			container.ID = evidence.ContainerID
			var containerBytes []byte
			switch name {
			case "malformed":
				containerBytes = []byte(`[{`)
			case "privileged":
				container.HostConfig.Privileged = true
				containerBytes, _ = json.Marshal([]dockerContainerInspection{container})
			case "id-mismatch":
				container.ID = strings.Repeat("e", 64)
				containerBytes, _ = json.Marshal([]dockerContainerInspection{container})
			}
			imageBytes, err := json.Marshal([]dockerImageInspection{image})
			require.NoError(t, err)
			containerArtifact := writeArtifact(t, evidence.ContainerInspectPath, containerBytes)
			imageArtifact := writeArtifact(t, evidence.ImageInspectPath, imageBytes)
			evidence.ContainerInspectSHA256 = containerArtifact.SHA256
			evidence.ImageInspectSHA256 = imageArtifact.SHA256
			evidenceBytes, err := json.Marshal(evidence)
			require.NoError(t, err)
			writeArtifact(t, fixture.contract.ContainerPreflightPath, evidenceBytes)
			_, err = verifyContainerPreflightEvidence(fixture.contract, contractPath, contractSHA)
			require.Error(t, err)
		})
	}
}

func materializeContainerPreflightRawFiles(t *testing.T, contract orchestrationContract, contractPath, contractSHA string, evidence *containerPreflightEvidence) {
	t.Helper()
	container, image := exactDockerInspection(t, contract, contractSHA)
	container.ID = evidence.ContainerID
	containerBytes, err := json.Marshal([]dockerContainerInspection{container})
	require.NoError(t, err)
	imageBytes, err := json.Marshal([]dockerImageInspection{image})
	require.NoError(t, err)
	containerArtifact := writeArtifact(t, evidence.ContainerInspectPath, containerBytes)
	imageArtifact := writeArtifact(t, evidence.ImageInspectPath, imageBytes)
	evidence.ContainerInspectSHA256 = containerArtifact.SHA256
	evidence.ImageInspectSHA256 = imageArtifact.SHA256
}

func exactDockerInspection(t *testing.T, contract orchestrationContract, contractSHA string) (dockerContainerInspection, dockerImageInspection) {
	t.Helper()
	var container dockerContainerInspection
	container.ID = strings.Repeat("d", 64)
	container.Name = "/" + contract.ContainerRuntime.Name
	container.Platform = "linux"
	container.Image = contract.ContainerRuntime.ImageID
	container.State.Status = "created"
	container.Config.Hostname = contract.ContainerRuntime.Hostname
	container.Config.User = fmt.Sprintf("%d:%d", contract.ContainerRuntime.UID, contract.ContainerRuntime.GID)
	container.Config.Entrypoint = []string{"/usr/bin/env"}
	container.Config.Cmd = expectedContainerCommand(contract, filepath.Join(contract.RehearsalRoot, "artifacts", "contract.json"), contractSHA)
	container.HostConfig.Binds = expectedContainerBinds(contract)
	container.HostConfig.NetworkMode = contract.ContainerRuntime.NetworkMode
	container.HostConfig.PIDMode = ""
	container.HostConfig.ReadonlyRootfs = true
	container.HostConfig.CapDrop = []string{"ALL"}
	container.HostConfig.IPCMode = "private"
	container.HostConfig.CgroupnsMode = "private"
	container.HostConfig.Runtime = "runc"
	seccompBytes, _, _ := readBoundFile(contract.SeccompProfile.Path, contract.SeccompProfile.SHA256)
	var compactSeccomp bytes.Buffer
	require.NoError(t, json.Compact(&compactSeccomp, seccompBytes))
	container.HostConfig.SecurityOpt = []string{"no-new-privileges", "seccomp=" + compactSeccomp.String()}
	container.HostConfig.RestartPolicy.Name = contract.ContainerRuntime.RestartPolicy
	container.HostConfig.PortBindings = map[string]interface{}{}
	for _, bind := range expectedContainerBinds(contract) {
		parts := strings.Split(bind, ":")
		container.Mounts = append(container.Mounts, struct {
			Type        string `json:"Type"`
			Source      string `json:"Source"`
			Destination string `json:"Destination"`
			Mode        string `json:"Mode"`
			RW          bool   `json:"RW"`
		}{Type: "bind", Source: parts[0], Destination: parts[1], Mode: parts[2], RW: parts[2] == "rw"})
	}
	image := dockerImageInspection{
		ID: contract.ContainerRuntime.ImageID, RepoDigests: []string{contract.ContainerRuntime.ImageRepoDigest},
		Architecture: "amd64", OS: "linux",
	}
	return container, image
}

func TestSeccompProfileIsHashBoundAndSemanticallyClosed(t *testing.T) {
	fixture := newOrchestrationFixture(t)
	require.NoError(t, verifySeccompProfile(fixture.contract.SeccompProfile))
	require.NoError(t, os.WriteFile(fixture.contract.SeccompProfile.Path, []byte(`{"defaultAction":"SCMP_ACT_ERRNO","defaultErrnoRet":1,"archMap":[],"syscalls":[]}`), 0o600))
	require.Error(t, verifySeccompProfile(fixture.contract.SeccompProfile))
	changed := writeArtifact(t, filepath.Join(fixture.root, "artifacts", "other-seccomp.json"), []byte(`{"defaultAction":"SCMP_ACT_ERRNO","defaultErrnoRet":1,"archMap":[],"syscalls":[]}`))
	require.ErrorContains(t, verifySeccompProfile(changed), "differs")
}

func TestTraceValidatorAllowsOnlyIsolatedLoopbackTopology(t *testing.T) {
	accepted := []string{
		`connect(4, {sa_family=AF_INET, sin_port=htons(9999), sin_addr=inet_addr("127.0.0.1")}, 16) = 0`,
		`bind(4, {sa_family=AF_INET, sin_port=htons(9999), sin_addr=inet_addr("0.0.0.0")}, 16) = 0`,
		`connect(4, {sa_family=AF_INET6, sin6_port=htons(9999), inet_pton(AF_INET6, "::1", &sin6_addr)}, 28) = 0`,
		`bind(4, {sa_family=AF_INET6, sin6_port=htons(9999), inet_pton(AF_INET6, "::", &sin6_addr)}, 28) = 0`,
		`connect(4, {sa_family=AF_UNIX, sun_path="/tmp/socket"}, 110) = 0`,
	}
	for _, line := range accepted {
		require.NoError(t, validateTracedNetworkLine(line), line)
	}
	rejected := []string{
		`connect(4, {sa_family=AF_INET, sin_addr=inet_addr("10.0.0.1")}, 16) = 0`,
		`connect(4, {sa_family=AF_INET, sin_addr=inet_addr("0.0.0.0")}, 16) = 0`,
		`bind(4, {sa_family=AF_INET, sin_addr=inet_addr("10.0.0.1")}, 16) = 0`,
		`connect(4, {sa_family=AF_INET6, inet_pton(AF_INET6, "2001:db8::1", &sin6_addr)}, 28) = 0`,
		`connect(4, {sa_family=AF_NETLINK}, 12) = 0`,
		`connect(4, <unfinished ...>`,
		`<... connect resumed>) = 0`,
	}
	for _, line := range rejected {
		require.Error(t, validateTracedNetworkLine(line), line)
	}
}

func TestVerifyAndHashTracesRequiresObservedParseableNetworkCall(t *testing.T) {
	root := t.TempDir()
	require.NoError(t, os.WriteFile(filepath.Join(root, "trace.1"), []byte("close(1) = 0\n"), 0o600))
	_, err := verifyAndHashTraces(root, []string{"trace"})
	require.ErrorContains(t, err, "no intercepted")
	require.NoError(t, os.WriteFile(filepath.Join(root, "trace.1"), []byte(`connect(4, {sa_family=AF_INET, sin_addr=inet_addr("127.0.0.1")}, 16) = 0`+"\n"), 0o600))
	hashes, err := verifyAndHashTraces(root, []string{"trace"})
	require.NoError(t, err)
	require.Len(t, hashes, 1)
	require.Len(t, hashes["trace.1"], 64)
	_, err = verifyAndHashTraces(root, []string{"trace", "missing"})
	require.ErrorContains(t, err, "missing")
	require.NoError(t, os.WriteFile(filepath.Join(root, "unexpected.2"), []byte(`bind(4, {sa_family=AF_INET, sin_addr=inet_addr("0.0.0.0")}, 16) = 0`+"\n"), 0o600))
	_, err = verifyAndHashTraces(root, []string{"trace"})
	require.ErrorContains(t, err, "unexpected trace prefix")
}

func TestExpectedTracePrefixesAreExactlyAllThirtyFourLaunches(t *testing.T) {
	fixture := newOrchestrationFixture(t)
	specs, err := deriveNodeSpecs(exactTopologyPlan(t, fixture), fixture.contract)
	require.NoError(t, err)
	observed := expectedTracePrefixes(specs, fixture.contract.CrashNodeID)
	expected := []string{"seed-seed", "post-crash-validator3"}
	for _, phase := range []string{"first", "second"} {
		for _, spec := range specs {
			expected = append(expected, phase+"-"+spec.ID)
		}
	}
	sort.Strings(expected)
	require.Len(t, observed, 34)
	require.Equal(t, expected, observed)
}

func TestPlanTopologyAndWriterEvidenceAreExactSets(t *testing.T) {
	fixture := newOrchestrationFixture(t)
	plan := exactTopologyPlan(t, fixture)
	require.NoError(t, validatePlanAgainstContract(plan, fixture.contract))
	specs, err := deriveNodeSpecs(plan, fixture.contract)
	require.NoError(t, err)
	require.Len(t, specs, 16)
	require.Equal(t, uint16(10000), specs[0].REST)
	require.Equal(t, uint16(9511), specs[15].REST)

	planSHA := strings.Repeat("a", 64)
	journalSHA := strings.Repeat("b", 64)
	completed := make([]string, 0, 16)
	for _, node := range plan.Nodes {
		completed = append(completed, node.ID)
	}
	writer := writerSummary{
		Schema:       "drwa.s1.prototype-network-identity-offline-rehearsal.v1",
		Status:       "ALL_SIXTEEN_EMERGENCY_IDENTITIES_DURABLE_NO_NODE_LAUNCHED_NO_RUNTIME_CREDIT",
		TimestampUTC: "2026-08-26T00:00:00Z",
		PlanPath:     fixture.contract.MigrationPlan.Path, PlanSHA256: planSHA,
		IdentityToolPath: fixture.contract.WriterIdentityTool.Path, IdentityToolSHA256: fixture.contract.WriterIdentityTool.SHA256,
		IsolationContractPath: fixture.contract.WriterIsolationContract.Path, IsolationContractSHA256: fixture.contract.WriterIsolationContract.SHA256,
		JournalPath: fixture.contract.WriterJournal.Path, JournalSHA256: journalSHA,
		CanonicalMetachainHash: plan.CanonicalHash, NetworkDomain: plan.NetworkDomain,
		Provenance: networkidentity.EmergencyMigration.String(), CompletedNodes: completed,
		DurableCloseReopenVerified: true,
	}
	require.NoError(t, validateWriterEvidence(writer, plan, fixture.contract, planSHA, journalSHA))
	for name, mutate := range map[string]func(*writerSummary){
		"plan path":         func(value *writerSummary) { value.PlanPath += ".other" },
		"plan hash":         func(value *writerSummary) { value.PlanSHA256 = strings.Repeat("0", 64) },
		"identity path":     func(value *writerSummary) { value.IdentityToolPath += ".other" },
		"identity hash":     func(value *writerSummary) { value.IdentityToolSHA256 = strings.Repeat("0", 64) },
		"contract path":     func(value *writerSummary) { value.IsolationContractPath += ".other" },
		"contract hash":     func(value *writerSummary) { value.IsolationContractSHA256 = strings.Repeat("0", 64) },
		"journal path":      func(value *writerSummary) { value.JournalPath += ".other" },
		"journal hash":      func(value *writerSummary) { value.JournalSHA256 = strings.Repeat("0", 64) },
		"canonical hash":    func(value *writerSummary) { value.CanonicalMetachainHash = strings.Repeat("0", 64) },
		"network domain":    func(value *writerSummary) { value.NetworkDomain = strings.Repeat("0", 64) },
		"provenance":        func(value *writerSummary) { value.Provenance = "LOCAL_CANONICAL_GENESIS" },
		"durability":        func(value *writerSummary) { value.DurableCloseReopenVerified = false },
		"runtime credit":    func(value *writerSummary) { value.AuthoritativeRuntimeCredit = 1 },
		"invalid timestamp": func(value *writerSummary) { value.TimestampUTC = "invalid" },
		"non-UTC timestamp": func(value *writerSummary) { value.TimestampUTC = "2026-08-26T01:00:00+01:00" },
		"noncanonical UTC":  func(value *writerSummary) { value.TimestampUTC = "2026-08-26T00:00:00.000Z" },
	} {
		t.Run("writer "+name, func(t *testing.T) {
			changed := writer
			mutate(&changed)
			require.Error(t, validateWriterEvidence(changed, plan, fixture.contract, planSHA, journalSHA))
		})
	}

	changedPlan := plan
	changedPlan.Nodes = append([]migrationPlanNode(nil), plan.Nodes...)
	changedPlan.Nodes[0].ShardID = "2"
	require.Error(t, validatePlanAgainstContract(changedPlan, fixture.contract))
	changedPlan = plan
	changedPlan.Nodes = append([]migrationPlanNode(nil), plan.Nodes...)
	changedPlan.Nodes[0].NodeRootDevice++
	require.ErrorContains(t, validatePlanAgainstContract(changedPlan, fixture.contract), "filesystem identity changed")
	changedPlan = plan
	changedPlan.Nodes = append([]migrationPlanNode(nil), plan.Nodes...)
	changedPlan.Nodes[0].TargetDBPath = filepath.Join(changedPlan.Nodes[0].NodeRoot, "target")
	require.ErrorContains(t, validatePlanAgainstContract(changedPlan, fixture.contract), "exact identity-store path")
	for name, mutate := range map[string]func(*migrationPlan){
		"candidate path": func(value *migrationPlan) { value.CandidateBinaryPath += ".other" },
		"candidate hash": func(value *migrationPlan) { value.CandidateBinarySHA256 = strings.Repeat("0", 64) },
		"validator path": func(value *migrationPlan) { value.ValidatorConfigPath = value.ObserverConfigPath },
		"validator hash": func(value *migrationPlan) { value.ValidatorConfigSHA256 = strings.Repeat("0", 64) },
		"observer path":  func(value *migrationPlan) { value.ObserverConfigPath = value.ValidatorConfigPath },
		"observer hash":  func(value *migrationPlan) { value.ObserverConfigSHA256 = strings.Repeat("0", 64) },
		"nodes setup":    func(value *migrationPlan) { value.NodesSetupSHA256 = strings.Repeat("0", 64) },
	} {
		t.Run("plan "+name, func(t *testing.T) {
			changed := plan
			mutate(&changed)
			require.Error(t, validatePlanAgainstContract(changed, fixture.contract))
		})
	}
	changedWriter := writer
	changedWriter.CompletedNodes = append([]string(nil), completed...)
	changedWriter.CompletedNodes[15] = changedWriter.CompletedNodes[0]
	require.Error(t, validateWriterEvidence(changedWriter, plan, fixture.contract, planSHA, journalSHA))
}

func TestValidatePlanRejectsSymlinkedWorkRootEvenWhenFilesystemIdentityMatches(t *testing.T) {
	fixture := newOrchestrationFixture(t)
	plan := exactTopologyPlan(t, fixture)
	originalRoot := plan.Nodes[0].NodeRoot
	relocatedRoot := originalRoot + "-relocated"
	require.NoError(t, os.Rename(originalRoot, relocatedRoot))
	require.NoError(t, os.Symlink(relocatedRoot, originalRoot))
	require.ErrorContains(t, validatePlanAgainstContract(plan, fixture.contract), "canonical/no-symlink")
}

func TestStartNodeRevalidatesWorkRootImmediatelyBeforeLaunch(t *testing.T) {
	work := t.TempDir()
	info, err := os.Stat(work)
	require.NoError(t, err)
	stat := info.Sys().(*syscall.Stat_t)
	launcher := processLauncher{}
	_, err = launcher.startNode(nodeSpec{
		ID: "validator3", Work: work, WorkRootDevice: uint64(stat.Dev), WorkRootInode: stat.Ino + 1,
	}, "first")
	require.ErrorContains(t, err, "work root changed before first launch")
}

func TestStopProcessesContinuesAfterEarlierProcessAlreadyExited(t *testing.T) {
	alreadyExited := &runningProcess{ID: "already-exited", done: make(chan error, 1), targetPIDFD: -1}
	alreadyExited.done <- errors.New("unexpected exit")
	fd, err := syscall.Dup(0)
	require.NoError(t, err)
	survivor := &runningProcess{ID: "survivor", done: make(chan error, 1), targetPID: 2, targetPIDFD: fd}
	signaled := make([]string, 0, 1)
	stopped, err := stopProcessesWithSignal(
		[]*runningProcess{alreadyExited, survivor}, time.Second, true,
		func(process *runningProcess) error {
			signaled = append(signaled, process.ID)
			process.done <- nil
			return nil
		},
	)
	require.ErrorContains(t, err, "already-exited")
	require.Equal(t, []string{"survivor"}, signaled)
	require.Equal(t, []string{"survivor"}, stopped)
	require.True(t, survivor.cleanStop)
}

func TestStartNodesReturnsEveryPartialLaunchForCallerOwnedCleanup(t *testing.T) {
	launched := make([]*runningProcess, 0, 2)
	launcher := processLauncher{
		startNodeOverride: func(spec nodeSpec, _ string) (*runningProcess, error) {
			if spec.ID == "third" {
				return nil, errors.New("injected third launch failure")
			}
			fd, err := syscall.Dup(0)
			require.NoError(t, err)
			process := &runningProcess{ID: spec.ID, done: make(chan error, 1), targetPID: 2, targetPIDFD: fd}
			launched = append(launched, process)
			return process, nil
		},
	}
	partial, err := launcher.startNodes([]nodeSpec{{ID: "first"}, {ID: "second"}, {ID: "third"}}, "phase")
	require.ErrorContains(t, err, "third launch failure")
	require.Equal(t, launched, partial)

	signaled := make([]string, 0, 2)
	stopped, cleanupErr := stopProcessesWithSignal(partial, time.Second, true, func(process *runningProcess) error {
		signaled = append(signaled, process.ID)
		process.done <- nil
		return nil
	})
	require.NoError(t, cleanupErr)
	require.Equal(t, []string{"first", "second"}, signaled)
	require.Equal(t, []string{"first", "second"}, stopped)
}

func TestTerminateUnboundProcessKillsAndBoundedlyReapsWholeGroup(t *testing.T) {
	command := exec.Command("/bin/sh", "-c", "sleep 30")
	command.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
	require.NoError(t, command.Start())
	process := &runningProcess{ID: "unbound", groupID: command.Process.Pid, done: make(chan error, 1), targetPIDFD: -1}
	go func() { process.done <- command.Wait() }()
	require.NoError(t, terminateUnboundProcess(process, 5*time.Second))
	require.True(t, process.crashed)
	require.Error(t, command.Process.Signal(syscall.Signal(0)))
}

func TestLoadBearingCleanupCallersRemainConnected(t *testing.T) {
	_, testPath, _, ok := runtime.Caller(0)
	require.True(t, ok)
	source, err := os.ReadFile(filepath.Join(filepath.Dir(testPath), "main.go"))
	require.NoError(t, err)
	text := string(source)
	for _, exact := range []string{
		"first, err := launcher.startNodes(specs, \"first\")\n\tallProcesses = append(allProcesses, first...)\n\tif err != nil",
		"second, err := launcher.startNodes(specs, \"second\")\n\tallProcesses = append(allProcesses, second...)\n\tif err != nil",
		"if !alreadyReaped {\n\t\t\tcleanupErr = terminateUnboundProcess(process, 5*time.Second)\n\t\t}",
		"return validateRuntimeMounts(string(mounts), contract)",
		"if err = verifyRuntimeSelf(contract, opts.contractPath, observedContractSHA); err != nil",
		"containerPreflightSHA, err := verifyContainerPreflightEvidence(contract, opts.contractPath, observedContractSHA)",
		"if err = validateHostPreflightSelfIdentity(os.Args[0], selfSHA, contract); err != nil",
		"if err := validateDigest(opts.expectedContractSHA); err != nil",
	} {
		require.Contains(t, text, exact)
	}
	require.GreaterOrEqual(t, strings.Count(text, "if err = verifyArtifactCollections(contract); err != nil"), 2)
}

func TestActualWriterArtifactsAreStrictlyConsumableReadOnly(t *testing.T) {
	planPath := os.Getenv("DRWA_ORCHESTRATOR_ACTUAL_PLAN")
	if planPath == "" {
		t.Skip("exact offline writer-artifact compatibility probe")
	}
	summaryPath := os.Getenv("DRWA_ORCHESTRATOR_ACTUAL_SUMMARY")
	journalPath := os.Getenv("DRWA_ORCHESTRATOR_ACTUAL_JOURNAL")
	writerContractPath := os.Getenv("DRWA_ORCHESTRATOR_ACTUAL_WRITER_CONTRACT")
	identityToolPath := os.Getenv("DRWA_ORCHESTRATOR_ACTUAL_IDENTITY_TOOL")
	for name, path := range map[string]string{
		"summary": summaryPath, "journal": journalPath,
		"writer contract": writerContractPath, "identity tool": identityToolPath,
	} {
		require.NotEmpty(t, path, name)
	}

	planBytes, planSHA, err := readBoundFile(planPath, os.Getenv("DRWA_ORCHESTRATOR_ACTUAL_PLAN_SHA"))
	require.NoError(t, err)
	var plan migrationPlan
	require.NoError(t, strictDecode(planBytes, &plan))

	summaryBytes, _, err := readBoundFile(summaryPath, os.Getenv("DRWA_ORCHESTRATOR_ACTUAL_SUMMARY_SHA"))
	require.NoError(t, err)
	var writer writerSummary
	require.NoError(t, strictDecode(summaryBytes, &writer))

	_, journalSHA, err := readBoundFile(journalPath, os.Getenv("DRWA_ORCHESTRATOR_ACTUAL_JOURNAL_SHA"))
	require.NoError(t, err)
	_, writerContractSHA, err := readBoundFile(writerContractPath, os.Getenv("DRWA_ORCHESTRATOR_ACTUAL_WRITER_CONTRACT_SHA"))
	require.NoError(t, err)
	_, identityToolSHA, err := readBoundFile(identityToolPath, os.Getenv("DRWA_ORCHESTRATOR_ACTUAL_IDENTITY_TOOL_SHA"))
	require.NoError(t, err)

	contract := orchestrationContract{
		RehearsalRoot:           plan.RehearsalRoot,
		CanonicalMetachainHash:  plan.CanonicalHash,
		NetworkDomain:           plan.NetworkDomain,
		CrashNodeID:             "validator3",
		MigrationPlan:           boundArtifact{Path: planPath, SHA256: planSHA},
		WriterJournal:           boundArtifact{Path: journalPath, SHA256: journalSHA},
		WriterIsolationContract: boundArtifact{Path: writerContractPath, SHA256: writerContractSHA},
		WriterIdentityTool:      boundArtifact{Path: identityToolPath, SHA256: identityToolSHA},
		NodeBinary:              boundArtifact{Path: plan.CandidateBinaryPath, SHA256: plan.CandidateBinarySHA256},
		NodeBase:                filepath.Join(plan.RehearsalRoot, "node-base"),
	}
	for _, relative := range []string{"config/config_validator.toml", "config/config_observer.toml", "config/nodesSetup.json"} {
		contract.NodeBaseFiles = append(contract.NodeBaseFiles, artifactFromPath(t, filepath.Join(contract.NodeBase, relative)))
	}
	require.NoError(t, validatePlanAgainstContract(plan, contract))
	require.NoError(t, validateWriterEvidence(writer, plan, contract, planSHA, journalSHA))
	require.NoError(t, verifyEveryStoredIdentity(plan))
}

func TestVerifyEveryStoredIdentityRejectsUnexpectedLogicalKey(t *testing.T) {
	fixture := newOrchestrationFixture(t)
	plan := exactTopologyPlan(t, fixture)
	headerBytes, err := (&marshal.GogoProtoMarshalizer{}).Marshal(&block.MetaBlock{
		Epoch: plan.CanonicalEpoch, ChainID: []byte(plan.ChainID),
		RootHash: []byte{1}, ValidatorStatsRootHash: []byte{2},
	})
	require.NoError(t, err)
	canonicalHash, domain, err := deriveCanonicalIdentity(plan, headerBytes)
	require.NoError(t, err)
	plan.CanonicalHash = hex.EncodeToString(canonicalHash[:])
	plan.NetworkDomain = hex.EncodeToString(domain[:])
	envelope, err := networkidentity.Encode(networkidentity.Record{
		SchemaVersion: networkidentity.Version,
		Epoch:         plan.CanonicalEpoch,
		Provenance:    networkidentity.EmergencyMigration,
		ChainID:       []byte(plan.ChainID),
		CanonicalHash: canonicalHash,
		NetworkDomain: domain,
		HeaderBytes:   headerBytes,
	})
	require.NoError(t, err)
	for _, node := range plan.Nodes {
		db, openErr := leveldb.OpenFile(node.TargetDBPath, nil)
		require.NoError(t, openErr)
		require.NoError(t, db.Put(networkidentity.Key(plan.CanonicalEpoch), envelope, nil))
		require.NoError(t, db.Close())
	}
	require.NoError(t, verifyEveryStoredIdentity(plan))

	db, err := leveldb.OpenFile(plan.Nodes[0].TargetDBPath, nil)
	require.NoError(t, err)
	require.NoError(t, db.Put([]byte("unexpected"), []byte("value"), nil))
	require.NoError(t, db.Close())
	require.ErrorContains(t, verifyEveryStoredIdentity(plan), "exactly the expected logical entry")
}

func TestFetchStatusAndBlockRejectMalformedRuntimeObservations(t *testing.T) {
	client := &http.Client{Timeout: time.Second, Transport: roundTripFunc(func(request *http.Request) (*http.Response, error) {
		var body string
		switch request.URL.Path {
		case "/node/status":
			body = `{"code":"successful","data":{"metrics":{"erd_shard_id":0,"erd_epoch_number":2,"erd_current_round":405,"erd_nonce":10,"erd_chain_id":"local-testnet"}}}`
		case "/block/by-nonce/10":
			body = `{"code":"successful","data":{"block":{"hash":"aa","stateRootHash":"bb","timestamp":123,"nonce":10,"shard":0}}}`
		default:
			return &http.Response{StatusCode: http.StatusNotFound, Body: http.NoBody, Header: make(http.Header)}, nil
		}
		return &http.Response{
			StatusCode: http.StatusOK, Header: make(http.Header),
			Body: io.NopCloser(strings.NewReader(body)), Request: request,
		}, nil
	})}
	status, err := fetchStatus(client, nodeSpec{ID: "observer0", REST: 12345})
	require.NoError(t, err)
	require.Equal(t, uint64(10), status.Nonce)
	block, err := fetchBlock(client, 12345, 10)
	require.NoError(t, err)
	require.Equal(t, "bb", block.StateRootHash)
}

func TestFetchStatusRejectsShardAboveUint32WithoutTruncation(t *testing.T) {
	client := &http.Client{Timeout: time.Second, Transport: roundTripFunc(func(request *http.Request) (*http.Response, error) {
		body := `{"code":"successful","data":{"metrics":{"erd_shard_id":4294967296,"erd_epoch_number":2,"erd_current_round":405,"erd_nonce":10,"erd_chain_id":"local-testnet"}}}`
		return &http.Response{
			StatusCode: http.StatusOK, Header: make(http.Header),
			Body: io.NopCloser(strings.NewReader(body)), Request: request,
		}, nil
	})}

	_, err := fetchStatus(client, nodeSpec{ID: "observer0", REST: 12345})
	require.ErrorContains(t, err, "status shard exceeds uint32 range")
}

func TestFetchBlockRejectsShardAboveUint32WithoutTruncation(t *testing.T) {
	client := &http.Client{Timeout: time.Second, Transport: roundTripFunc(func(request *http.Request) (*http.Response, error) {
		body := `{"code":"successful","data":{"block":{"hash":"aa","stateRootHash":"bb","timestamp":123,"nonce":10,"shard":4294967296}}}`
		return &http.Response{
			StatusCode: http.StatusOK, Header: make(http.Header),
			Body: io.NopCloser(strings.NewReader(body)), Request: request,
		}, nil
	})}

	_, err := fetchBlock(client, 12345, 10)
	require.ErrorContains(t, err, "block shard exceeds uint32 range")
}

func TestRuntimeObservationDecoderRejectsTrailingValuesAndDuplicateKeys(t *testing.T) {
	status := `{"code":"successful","data":{"metrics":{"erd_shard_id":0,"erd_epoch_number":2,"erd_current_round":405,"erd_nonce":10,"erd_chain_id":"local-testnet"}}}`
	block := `{"code":"successful","data":{"block":{"hash":"aa","stateRootHash":"bb","timestamp":123,"nonce":10,"shard":0}}}`
	tests := []struct {
		name string
		path string
		body string
		call func(*http.Client) error
	}{
		{name: "status trailing value", path: "/node/status", body: status + `{"forged":true}`, call: func(client *http.Client) error {
			_, err := fetchStatus(client, nodeSpec{ID: "observer0", REST: 12345})
			return err
		}},
		{name: "block trailing value", path: "/block/by-nonce/10", body: block + `{"forged":true}`, call: func(client *http.Client) error {
			_, err := fetchBlock(client, 12345, 10)
			return err
		}},
		{name: "status duplicate nested key", path: "/node/status", body: strings.Replace(status, `"erd_shard_id":0`, `"erd_shard_id":0,"erd_shard_id":1`, 1), call: func(client *http.Client) error {
			_, err := fetchStatus(client, nodeSpec{ID: "observer0", REST: 12345})
			return err
		}},
		{name: "block duplicate nested key", path: "/block/by-nonce/10", body: strings.Replace(block, `"shard":0`, `"shard":0,"shard":1`, 1), call: func(client *http.Client) error {
			_, err := fetchBlock(client, 12345, 10)
			return err
		}},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			client := &http.Client{Timeout: time.Second, Transport: roundTripFunc(func(request *http.Request) (*http.Response, error) {
				require.Equal(t, test.path, request.URL.Path)
				return &http.Response{
					StatusCode: http.StatusOK, Header: make(http.Header),
					Body: io.NopCloser(strings.NewReader(test.body)), Request: request,
				}, nil
			})}
			require.Error(t, test.call(client))
		})
	}
}

func TestRuntimeObservationDecoderAllowsUnmodeledFields(t *testing.T) {
	body := `{"code":"successful","extra":"retained-api-field","data":{"metrics":{"erd_shard_id":0,"erd_epoch_number":2,"erd_current_round":405,"erd_nonce":10,"erd_chain_id":"local-testnet","erd_extra_metric":7}}}`
	client := &http.Client{Timeout: time.Second, Transport: roundTripFunc(func(request *http.Request) (*http.Response, error) {
		return &http.Response{
			StatusCode: http.StatusOK, Header: make(http.Header),
			Body: io.NopCloser(strings.NewReader(body)), Request: request,
		}, nil
	})}

	status, err := fetchStatus(client, nodeSpec{ID: "observer0", REST: 12345})
	require.NoError(t, err)
	require.Equal(t, uint32(0), status.ShardID)
}

type roundTripFunc func(*http.Request) (*http.Response, error)

func (function roundTripFunc) RoundTrip(request *http.Request) (*http.Response, error) {
	return function(request)
}

func TestStrictDecodeAndAnchorEqualityFailClosed(t *testing.T) {
	var value struct {
		A int `json:"a"`
	}
	require.NoError(t, strictDecode([]byte(`{"a":1}`), &value))
	require.Error(t, strictDecode([]byte(`{"a":1,"a":2}`), &value))
	require.Error(t, strictDecode([]byte(`{"a":1,"unknown":2}`), &value))
	require.Error(t, strictDecode([]byte(`{"a":1}{"a":2}`), &value))

	anchors := map[string]blockObservation{}
	for _, shard := range []string{"0", "1", "2", "metachain"} {
		anchors[shard] = blockObservation{Hash: shard, StateRootHash: "root-" + shard, Nonce: 1}
	}
	require.NoError(t, equalAnchors(anchors, cloneAnchors(anchors)))
	changed := cloneAnchors(anchors)
	entry := changed["1"]
	entry.StateRootHash = "wrong"
	changed["1"] = entry
	require.Error(t, equalAnchors(anchors, changed))
	delete(changed, "2")
	require.Error(t, equalAnchors(anchors, changed))
}

type orchestrationFixture struct {
	root     string
	contract orchestrationContract
}

func newOrchestrationFixture(t *testing.T) orchestrationFixture {
	t.Helper()
	root := t.TempDir()
	artifacts := filepath.Join(root, "artifacts")
	nodeBase := filepath.Join(root, "node-base")
	seedRoot := filepath.Join(root, "seed")
	traceRoot := filepath.Join(root, "trace-libs")
	runtimeRoot := filepath.Join(root, "runtime-libs")
	for _, directory := range []string{artifacts, nodeBase, seedRoot, traceRoot, runtimeRoot, filepath.Join(root, "runtime", "home"), filepath.Join(root, "runtime", "tmp")} {
		require.NoError(t, os.MkdirAll(directory, 0o700))
	}
	nodeFiles := []boundArtifact{
		writeArtifact(t, filepath.Join(nodeBase, "config", "config_validator.toml"), []byte("node-config")),
		writeArtifact(t, filepath.Join(nodeBase, "config", "config_observer.toml"), []byte("node-config")),
		writeArtifact(t, filepath.Join(nodeBase, "config", "nodesSetup.json"), []byte("nodes-setup")),
	}
	seedFiles := []boundArtifact{writeArtifact(t, filepath.Join(seedRoot, "config.toml"), []byte("seed"))}
	traceLibraries := []boundArtifact{writeArtifact(t, filepath.Join(traceRoot, "libc.so"), []byte("lib"))}
	runtimeLibraries := []boundArtifact{writeArtifact(t, filepath.Join(runtimeRoot, "libwasmer.so"), []byte("lib"))}
	writeArtifact(t, filepath.Join(artifacts, "config_validator.toml"), []byte("node-config"))
	writeArtifact(t, filepath.Join(artifacts, "config_observer.toml"), []byte("node-config"))
	seccompProfile := writeArtifact(t, filepath.Join(artifacts, "seccomp.json"), []byte(`{"defaultAction":"SCMP_ACT_ALLOW","defaultErrnoRet":1,"archMap":[{"architecture":"SCMP_ARCH_X86_64","subArchitectures":["SCMP_ARCH_X86","SCMP_ARCH_X32"]}],"syscalls":[]}`))
	contract := orchestrationContract{
		Schema: contractSchema, Status: contractStatus, CreatedUTC: "2026-08-26T00:00:00Z",
		RehearsalRoot: root, HostNetworkNamespace: "net:[host]",
		MigrationPlan:           writeArtifact(t, filepath.Join(artifacts, "plan.json"), []byte("plan")),
		WriterSummary:           writeArtifact(t, filepath.Join(artifacts, "summary.json"), []byte("summary")),
		WriterJournal:           writeArtifact(t, filepath.Join(artifacts, "journal.jsonl"), []byte("journal")),
		WriterIsolationContract: writeArtifact(t, filepath.Join(artifacts, "writer-contract.json"), []byte("writer-contract")),
		WriterBinary:            writeArtifact(t, filepath.Join(artifacts, "writer"), []byte("writer")),
		WriterIdentityTool:      writeArtifact(t, filepath.Join(artifacts, "identity-tool"), []byte("identity-tool")),
		WriterStoppedPreflight:  writeArtifact(t, filepath.Join(artifacts, "writer-preflight.json"), []byte("writer-preflight")),
		WriterContainerEvents:   writeArtifact(t, filepath.Join(artifacts, "writer-events.jsonl"), []byte("writer-events")),
		WriterPostRunState:      writeArtifact(t, filepath.Join(artifacts, "writer-state.json"), []byte("writer-state")),
		WriterLogsEvidence:      writeArtifact(t, filepath.Join(artifacts, "writer-logs.json"), []byte("writer-logs")),
		NodeBinary:              writeArtifact(t, filepath.Join(artifacts, "node"), []byte("node-bin")),
		NodeBase:                nodeBase, NodeBaseFiles: nodeFiles,
		SeedBinary: writeArtifact(t, filepath.Join(artifacts, "seednode"), []byte("seed-bin")),
		SeedRoot:   seedRoot, SeedFiles: seedFiles,
		TraceLoader:           writeArtifact(t, filepath.Join(artifacts, "loader"), []byte("loader")),
		TraceBinary:           writeArtifact(t, filepath.Join(artifacts, "strace"), []byte("strace")),
		TraceLibraryDirectory: traceRoot, TraceLibraries: traceLibraries,
		RuntimeLibraryDirectory: runtimeRoot, RuntimeLibraries: runtimeLibraries,
		ChildEnvironment: []string{
			"HOME=" + filepath.Join(root, "runtime", "home"), "LANG=C.UTF-8", "LC_ALL=C.UTF-8",
			"LD_LIBRARY_PATH=" + runtimeRoot, "PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin",
			"TMPDIR=" + filepath.Join(root, "runtime", "tmp"),
		},
		SeccompProfile:           seccompProfile,
		ReadOnlyMounts:           []string{nodeBase, seedRoot, traceRoot, runtimeRoot, seccompProfile.Path},
		ExpectedGenesisTimestamp: 1,
		CanonicalMetachainHash:   strings.Repeat("1", 64), NetworkDomain: strings.Repeat("2", 64),
		IdentityProvenance: networkidentity.EmergencyMigration.String(), CrashNodeID: "validator3",
		HealthTimeoutSeconds: 30, ShutdownTimeoutSeconds: 10,
		EvidencePath: filepath.Join(artifacts, "evidence.json"), JournalPath: filepath.Join(artifacts, "orchestration.jsonl"),
		ContainerPreflightPath: filepath.Join(artifacts, "container-preflight.json"),
	}
	contract.ContainerRuntime = containerRuntimeContract{
		ImageID: "sha256:" + strings.Repeat("a", 64), ImageRepoDigest: "rust@sha256:" + strings.Repeat("a", 64),
		Platform: "linux/amd64", Name: "drwa-orchestrator-test", Hostname: "drwa-orchestrator-test",
		UID: 1001, GID: 1001, NetworkMode: "none", PIDMode: "private", RestartPolicy: "no", PullPolicy: "never",
		ReadOnlyRootFS: true, AutoRemove: false,
		Orchestrator: writeArtifact(t, filepath.Join(artifacts, "orchestrator"), []byte("orchestrator")),
		Environment:  append([]string(nil), contract.ChildEnvironment...),
	}
	contract.ReadOnlyMounts = append(contract.ReadOnlyMounts, contract.ContainerRuntime.Orchestrator.Path)
	return orchestrationFixture{root: root, contract: contract}
}

func exactTopologyPlan(t *testing.T, fixture orchestrationFixture) migrationPlan {
	t.Helper()
	plan := migrationPlan{
		Schema: planSchema, Status: "READY_OFFLINE_REHEARSAL_NO_LIVE_AUTHORIZATION",
		CreatedUTC: "2026-08-26T00:00:00Z",
		ChainID:    "local-testnet", CanonicalHash: fixture.contract.CanonicalMetachainHash,
		NetworkDomain: fixture.contract.NetworkDomain, RehearsalRoot: fixture.root,
	}
	plan.CandidateBinaryPath = fixture.contract.NodeBinary.Path
	plan.CandidateBinarySHA256 = fixture.contract.NodeBinary.SHA256
	plan.ValidatorConfigPath = filepath.Join(fixture.root, "artifacts", "config_validator.toml")
	_, plan.ValidatorConfigSHA256, _ = readBoundFile(plan.ValidatorConfigPath, "")
	plan.ObserverConfigPath = filepath.Join(fixture.root, "artifacts", "config_observer.toml")
	_, plan.ObserverConfigSHA256, _ = readBoundFile(plan.ObserverConfigPath, "")
	plan.NodesSetupSHA256, _ = boundArtifactSHA(fixture.contract.NodeBaseFiles, filepath.Join(fixture.contract.NodeBase, "config", "nodesSetup.json"))
	observerShards := []string{"0", "1", "2", "metachain"}
	for index, shard := range observerShards {
		root := filepath.Join(fixture.root, "work", fmt.Sprintf("observer%d", index))
		target := filepath.Join(root, "db", plan.ChainID, "Static", "Shard_"+shard, "PrototypeNetworkIdentityStorageDB")
		require.NoError(t, os.MkdirAll(target, 0o700))
		info, err := os.Stat(root)
		require.NoError(t, err)
		stat := info.Sys().(*syscall.Stat_t)
		plan.Nodes = append(plan.Nodes, migrationPlanNode{
			ID: fmt.Sprintf("observer%d", index), Role: "observer", ShardID: shard,
			SourceRootDevice: 1, SourceRootInode: uint64(index + 1),
			NodeRoot: root, NodeRootDevice: uint64(stat.Dev), NodeRootInode: stat.Ino, TargetDBPath: target,
		})
	}
	validatorShards := []string{"metachain", "metachain", "metachain", "0", "0", "0", "1", "1", "1", "2", "2", "2"}
	for index, shard := range validatorShards {
		root := filepath.Join(fixture.root, "work", fmt.Sprintf("validator%d", index))
		target := filepath.Join(root, "db", plan.ChainID, "Static", "Shard_"+shard, "PrototypeNetworkIdentityStorageDB")
		require.NoError(t, os.MkdirAll(target, 0o700))
		info, err := os.Stat(root)
		require.NoError(t, err)
		stat := info.Sys().(*syscall.Stat_t)
		plan.Nodes = append(plan.Nodes, migrationPlanNode{
			ID: fmt.Sprintf("validator%d", index), Role: "validator", ShardID: shard,
			SourceRootDevice: 1, SourceRootInode: uint64(index + 101),
			NodeRoot: root, NodeRootDevice: uint64(stat.Dev), NodeRootInode: stat.Ino, TargetDBPath: target,
		})
	}
	return plan
}

func writeArtifact(t *testing.T, path string, value []byte) boundArtifact {
	t.Helper()
	require.NoError(t, os.MkdirAll(filepath.Dir(path), 0o700))
	require.NoError(t, os.WriteFile(path, value, 0o700))
	digest := sha256.Sum256(value)
	return boundArtifact{Path: path, SHA256: hex.EncodeToString(digest[:])}
}

func cloneContract(t *testing.T, value orchestrationContract) orchestrationContract {
	t.Helper()
	encoded, err := json.Marshal(value)
	require.NoError(t, err)
	var cloned orchestrationContract
	require.NoError(t, json.Unmarshal(encoded, &cloned))
	return cloned
}

func cloneStrings(value map[string]string) map[string]string {
	result := make(map[string]string, len(value))
	for key, field := range value {
		result[key] = field
	}
	return result
}

func cloneAnchors(value map[string]blockObservation) map[string]blockObservation {
	result := make(map[string]blockObservation, len(value))
	for key, field := range value {
		result[key] = field
	}
	return result
}

func TestNumericValueRejectsLossyOrNegativeValues(t *testing.T) {
	value, err := numericValue(json.Number("18446744073709551615"))
	require.NoError(t, err)
	require.Equal(t, ^uint64(0), value)
	_, err = numericValue(float64(-1))
	require.Error(t, err)
	_, err = numericValue(1.25)
	require.Error(t, err)
	_, err = numericValue(errors.New("not numeric"))
	require.Error(t, err)
}

func TestTracedProcessSupervisionHasCleanStopAndCrashBoundaries(t *testing.T) {
	testExecutable, err := os.Executable()
	require.NoError(t, err)
	testExecutable, err = filepath.EvalSymlinks(testExecutable)
	require.NoError(t, err)
	loaderPath := environmentOrDefault("DRWA_TRACE_TEST_LOADER", "/usr/lib/x86_64-linux-gnu/ld-linux-x86-64.so.2")
	tracePath := environmentOrDefault("DRWA_TRACE_TEST_BINARY", "/usr/bin/strace")
	traceLibraryPath := environmentOrDefault("DRWA_TRACE_TEST_LIBRARY_DIRECTORY", "/usr/lib/x86_64-linux-gnu")
	for _, path := range []string{loaderPath, tracePath, traceLibraryPath, testExecutable} {
		if _, err := os.Stat(path); err != nil {
			t.Skipf("required local supervision probe artifact unavailable: %s", path)
		}
	}
	root := t.TempDir()
	traceDir := filepath.Join(root, "traces")
	logDir := filepath.Join(root, "logs")
	require.NoError(t, os.Mkdir(traceDir, 0o700))
	require.NoError(t, os.Mkdir(logDir, 0o700))
	loader, err := openSealedFile(artifactFromPath(t, loaderPath))
	require.NoError(t, err)
	defer loader.Close()
	tracer, err := openSealedFile(artifactFromPath(t, tracePath))
	require.NoError(t, err)
	defer tracer.Close()
	target, err := openSealedFile(artifactFromPath(t, testExecutable))
	require.NoError(t, err)
	defer target.Close()
	t.Setenv("DRWA_TRACED_PROCESS_SIGNAL_HELPER", "1")
	launcher := processLauncher{
		contract:    orchestrationContract{TraceLibraryDirectory: traceLibraryPath, ShutdownTimeoutSeconds: 10, ChildEnvironment: os.Environ()},
		traceLoader: loader, traceBinary: tracer, traceDir: traceDir, logDir: logDir,
	}

	helperArgs := []string{"-test.run=^TestTracedProcessSignalHelper$", "-test.timeout=30s"}
	clean, err := launcher.start("clean", target, helperArgs, root, "probe")
	if err != nil {
		logBytes, _ := os.ReadFile(filepath.Join(logDir, "probe-clean.log"))
		if strings.Contains(string(logBytes), "PTRACE_TRACEME: Operation not permitted") {
			if os.Getenv("DRWA_TRACE_TEST_REQUIRE_PTRACE") == "1" {
				t.Fatalf("bound container profile blocks required ptrace: %v; log=%s", err, logBytes)
			}
			t.Skip("host test sandbox blocks ptrace; the identical positive probe is mandatory under the bound container seccomp profile")
		}
		t.Fatalf("start clean traced process: %v; log=%s", err, logBytes)
	}
	time.Sleep(100 * time.Millisecond)
	stopped, err := stopProcesses([]*runningProcess{clean}, 5*time.Second, true)
	if err != nil {
		logBytes, _ := os.ReadFile(filepath.Join(logDir, "probe-clean.log"))
		if strings.Contains(string(logBytes), "PTRACE_TRACEME: Operation not permitted") {
			if os.Getenv("DRWA_TRACE_TEST_REQUIRE_PTRACE") == "1" {
				t.Fatalf("bound container profile blocks required ptrace during stop: %v; log=%s", err, logBytes)
			}
			t.Skip("host test sandbox blocks ptrace; the identical positive probe is mandatory under the bound container seccomp profile")
		}
		t.Fatalf("clean traced-process stop: %v; log=%s", err, logBytes)
	}
	require.Equal(t, []string{"clean"}, stopped)

	crashed, err := launcher.start("crash", target, helperArgs, root, "probe")
	require.NoError(t, err)
	time.Sleep(100 * time.Millisecond)
	require.NoError(t, killProcess(crashed, 5*time.Second))
	require.True(t, crashed.crashed)
}

func environmentOrDefault(name, fallback string) string {
	if value := os.Getenv(name); value != "" {
		return value
	}
	return fallback
}

func TestTracedProcessSignalHelper(t *testing.T) {
	if os.Getenv("DRWA_TRACED_PROCESS_SIGNAL_HELPER") != "1" {
		t.Skip("only executed as the sealed traced-process supervision target")
	}
	signals := make(chan os.Signal, 1)
	signal.Notify(signals, syscall.SIGTERM)
	defer signal.Stop(signals)
	<-signals
}

func artifactFromPath(t *testing.T, path string) boundArtifact {
	t.Helper()
	value, err := os.ReadFile(path)
	require.NoError(t, err)
	digest := sha256.Sum256(value)
	return boundArtifact{Path: path, SHA256: hex.EncodeToString(digest[:])}
}
