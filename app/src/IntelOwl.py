from pyintelowl import IntelOwl
import time


class IntelOwlExtended(IntelOwl):
    def parse(self, result):
        pass

    def poll_for_job(
        self,
        job_id: list,
        max_tries=10,
        interval=5,
    ):
        ans = None
        for i in range(max_tries):
            if i != 0:
                time.sleep(interval)
            ans = [self.get_job_by_id(a) for a in job_id]
            for a in ans:
                if a["status"].lower() not in ["running", "pending"]:
                    job_id.remove(a["id"])
                    yield self.parse(a)
            if job_id == []:
                break
