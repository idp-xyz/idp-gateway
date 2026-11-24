"""deploy/kubernetes/egress: base + kind overlay shape (offline).

Locks replica counts, Recreate on coordinators, NetworkPolicy presence, and that the
kind overlay strips --gatekeeper-* from gateway-authz. Not an acceptance pass.
"""
import unittest
from pathlib import Path
import yaml

R = Path(__file__).resolve().parents[2]


def load_kustomize_docs():
    import subprocess
    kubectl = Path.home() / ".local/bin/kubectl"
    cmd = [str(kubectl) if kubectl.exists() else "kubectl", "kustomize",
           str(R / "deploy/kubernetes/egress/overlays/kind")]
    done = subprocess.run(cmd, capture_output=True, text=True, timeout=60)
    if done.returncode != 0:
        raise RuntimeError(done.stderr[-500:])
    return [d for d in yaml.safe_load_all(done.stdout) if d]


class K8sEgressOverlay(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.docs = load_kustomize_docs()
        cls.by = {}
        for d in cls.docs:
            cls.by.setdefault(d["kind"], []).append(d)

    def test_kinds_present(self):
        for kind in ("Namespace", "Deployment", "Service", "NetworkPolicy", "PersistentVolumeClaim"):
            self.assertIn(kind, self.by, kind)

    def test_replica_counts_and_recreate(self):
        want = {
            "gateway": (2, "RollingUpdate"),
            "gateway-authz": (2, "RollingUpdate"),
            "provider-signer": (2, "RollingUpdate"),
            "sf-token-coordinator": (1, "Recreate"),
            "authz-state": (1, "Recreate"),
        }
        found = {d["metadata"]["name"]: d for d in self.by["Deployment"]}
        for name, (replicas, strategy) in want.items():
            with self.subTest(name):
                self.assertEqual(found[name]["spec"]["replicas"], replicas)
                self.assertEqual(found[name]["spec"]["strategy"]["type"], strategy)

    def test_kind_overlay_strips_gatekeeper_flags(self):
        authz = next(d for d in self.by["Deployment"] if d["metadata"]["name"] == "gateway-authz")
        args = authz["spec"]["template"]["spec"]["containers"][0]["args"]
        self.assertTrue(any(a.startswith("--sf-openapi-lease-url=") for a in args))
        self.assertTrue(any(a.startswith("--authz-state-url=") for a in args))
        self.assertFalse(any("gatekeeper" in a for a in args))

    def test_default_deny_network_policy(self):
        names = {d["metadata"]["name"] for d in self.by["NetworkPolicy"]}
        self.assertIn("default-deny-all", names)
        deny = next(d for d in self.by["NetworkPolicy"] if d["metadata"]["name"] == "default-deny-all")
        self.assertEqual(set(deny["spec"]["policyTypes"]), {"Ingress", "Egress"})
        self.assertEqual(deny["spec"].get("podSelector"), {})

    def test_pod_security_context_fields(self):
        for d in self.by["Deployment"]:
            with self.subTest(d["metadata"]["name"]):
                psc = d["spec"]["template"]["spec"]["securityContext"]
                self.assertTrue(psc.get("runAsNonRoot"))
                self.assertEqual((psc.get("seccompProfile") or {}).get("type"), "RuntimeDefault")
                for c in d["spec"]["template"]["spec"]["containers"]:
                    sc = c["securityContext"]
                    self.assertTrue(sc.get("readOnlyRootFilesystem"))
                    self.assertFalse(sc.get("allowPrivilegeEscalation"))
                    self.assertEqual((sc.get("capabilities") or {}).get("drop"), ["ALL"])


if __name__ == "__main__":
    unittest.main()
