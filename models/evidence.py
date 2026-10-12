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

    def to_dict(self):
        return {
            "namespace": self.namespace,
            "pod": self.pod,
            "status": self.status,
            "restarts": self.restarts,
            "events": self.events,
            "logs": self.logs,
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
