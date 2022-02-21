from datetime import datetime

class Converter:
    def __init__(self, type) -> None:
        self.type = type
        self.hour = str(datetime.utcnow()).split(" ")
        self.expiration = ""

    def converter(self):
        date = self.hour[0].split("-")
        if(self.type == "files/"):
            nextYear = int(date[0]) + 1
            nextMonth = date[1]
        else:
            nextMonth = int(date[1]) + 3
            nextYear = int(date[0])
            if(nextMonth>=0 and nextMonth<10):
                nextMonth = "0" + str(nextMonth)
            if(int(date[1])>12):
                nextMonth = nextMonth - 12
                nextMonth = "0" + str(nextMonth)
                nextYear = int(date[0]) + 1

        self.expiration = str(nextYear) + "-" + str(nextMonth) + "-" + str(date[2]) + "T" + str(datetime.utcnow()).split(" ")[1] + "Z"
        return self.expiration