import unittest
from pathlib import Path


class DeployWorkflowTests(unittest.TestCase):
    def test_deployer_does_not_apply_namespace_rbac(self):
        repository_root = Path(__file__).resolve().parents[1]
        workflow = (
            repository_root / ".github" / "workflows" / "deploy.yml"
        ).read_text(encoding="utf-8")

        self.assertIn("kubectl apply -f k8s/namespace.yaml", workflow)
        self.assertIn('kubectl apply -f "${RUNNER_TEMP}/deployment.yaml"', workflow)
        self.assertIn("kubectl apply -f k8s/service.yaml", workflow)
        self.assertNotIn("kubectl apply -f k8s/troubleshooter-rbac.yaml", workflow)

    def test_rbac_manifest_remains_documented_as_operator_provisioned(self):
        repository_root = Path(__file__).resolve().parents[1]
        readme = (repository_root / "README.md").read_text(encoding="utf-8")

        self.assertIn("authorized to create namespace Roles and RoleBindings", readme)
        self.assertIn("the deployer is not granted permission to create or modify Roles or RoleBindings", readme)


if __name__ == "__main__":
    unittest.main()
