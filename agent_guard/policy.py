"""No side effects: newest eligible work wins, never an arbitrary process."""


def choose_victim(jobs, total, limit, complete, min_bytes):
    if not complete or total <= limit:
        return None
    candidates = [j for j in jobs if not j.baseline and not j.tainted and j.pss >= min_bytes]
    return max(candidates, key=lambda j: (j.start, j.root_pid), default=None)


class Gate:
    def __init__(self, grace, samples, cooldown, started):
        self.grace, self.samples, self.cooldown = grace, samples, cooldown
        self.started, self.last, self.count = started, float('-inf'), 0

    def ready(self, now, over, complete):
        if not complete or not over or now - self.started < self.grace:
            self.count = 0
            return False
        self.count += 1
        return self.count >= self.samples and now - self.last >= self.cooldown

    def acted(self, now):
        self.last, self.count = now, 0
