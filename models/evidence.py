class IncidentEvidence:
    def __init__(
        self,
        namespace,
        pod,
        status,
        restarts,
        events,
        logs,
        cpu=None,
        memory=None,
        last_termination_reason=None,
        last_exit_code=None,
        last_termination_message=None,
        cluster=None,
        workload=None,
        workload_kind=None,
        node=None,
        ready=None,
        containers=None,
        metrics=None,
        observed_at=None,
        source_status=None,
    ):
        self.namespace = namespace
        self.pod = pod
        self.status = status
        self.restarts = restarts
        self.events = events
        self.logs = logs
        self.cpu = cpu
        self.memory = memory
        self.last_termination_reason = last_termination_reason
        self.last_exit_code = last_exit_code
        self.last_termination_message = last_termination_message
        self.cluster = cluster
        self.workload = workload
        self.workload_kind = workload_kind
        self.node = node
        self.ready = ready
        self.containers = containers or []
        self.metrics = metrics or []
        self.observed_at = observed_at
        self.source_status = source_status or {}

    def to_dict(self):
        return {
            "cluster": self.cluster,
            "namespace": self.namespace,
            "workload": self.workload,
            "workload_kind": self.workload_kind,
            "pod": self.pod,
            "node": self.node,
            "status": self.status,
            "ready": self.ready,
            "restarts": self.restarts,
            "containers": self.containers,
            "events": self.events,
            "logs": self.logs,
            "metrics": self.metrics,
            "observed_at": self.observed_at,
            "source_status": self.source_status,
            "cpu": self.cpu,
            "memory": self.memory,
            "last_termination_reason": self.last_termination_reason,
            "last_exit_code": self.last_exit_code,
            "last_termination_message": self.last_termination_message,
        }

    def display(self):
        print("\n========== INCIDENT EVIDENCE ==========\n")
        print(f"Namespace          : {self.namespace}")
        print(f"Pod                : {self.pod}")
        print(f"Status             : {self.status}")
        print(f"Restarts           : {self.restarts}")
        print(f"CPU                : {self.cpu}")
        print(f"Memory             : {self.memory}")
        print(f"Last termination   : {self.last_termination_reason}")
        print(f"Last exit code     : {self.last_exit_code}")
        print(f"Termination message: {self.last_termination_message}")

        print("\nEvents:")
        for event in self.events:
            print(f"  - {event}")

        print("\nLogs:")
        for log in self.logs:
            print(f"  - {log}")
