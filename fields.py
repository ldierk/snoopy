from datetime import datetime
DATE_FORMAT = r"%Y-%m-%d-%H:%M:%S.%f%z"
DATE_FORMAT_OUT = r"%Y-%m-%d-%H:%M:%S.%f"


def fix_date(date):
    # limit milliseconds to 3 digits
    datestr = date.strftime(DATE_FORMAT_OUT)
    datestr = datestr[:-3]
    # insert a colon between hour and minutes in the timezone offset
    tz = date.strftime("%z")
    tz = tz[:3] + ":" + tz[3:]
    return "{}{}".format(datestr, tz)


class Header:
    def __init__(self, re, line):
        matches = re.search(line)
        self.date = datetime.strptime(matches.group("date"), DATE_FORMAT)
        self.thread = int(matches.group("thread"))
        self.component = matches.group("component")
        self.source_file = matches.group("file")
        self.error_message = matches.group("remainder").strip()

    def is_error(self) -> bool:
        return self.error_message

    def __str__(self):
        return "{}I----- thread({}) {} {} {}".format(fix_date(self.date), self.thread,  self.component,  self.source_file, self.error_message)


class Summary:
    def __init__(self, re, line):
        matches = re.search(line)
        self.thread = int(matches.group("thread"))
        self.fd = int(matches.group("fd"))
        self.message = matches.group("remainder").strip()

    def has_action(self):
        return not self.message.startswith("failed")

    def __str__(self):
        return "Thread {}; fd {}; {}".format(self.thread, self.fd, self.message)


class Action:
    def __init__(self, line):
        self.action = line

    def has_data(self) -> bool:
        return self.action.startswith("Sending") or self.action.startswith("Receiving")

    def __str__(self):
        return self.action
