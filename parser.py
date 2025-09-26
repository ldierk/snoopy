import re
from enum import Enum
from enum import auto
from io import StringIO
import fields


HEADER_REGEX = r"(?P<date>\d\d\d\d-\d\d-\d\d-\d\d:\d\d:\d\d.\d\d\d\+\d\d:\d\d)I-----" + \
    r" thread\((?P<thread>\d+)\)" + \
    r" (?P<component>.+) (?P<file>.+:\d+:)(?P<remainder>.*)"
SUMMARY_REGEX = r"Thread (?P<thread>\d+); fd (?P<fd>\d+);(?P<remainder>.*)"
DATA_REGEX = r"^0x[a-zA-Z0-9]{4}"
LIMITTER = "----------------------------------------"
START_OF_TEXT = 56


class State(Enum):
    HEADER = auto()
    OPENING_LIMIT = auto()
    SUMMARY = auto()
    ACTION = auto()
    DATA = auto()
    CLOSING_LIMIT = auto()


def snoop_to_text(line) -> str:
    return line[START_OF_TEXT:]


def format_data(data, length):
    return "\n".join(list((data[0+i:length+i] for i in range(0, len(data), length))))


class SnoopConfig:
    def __init__(self, filename="pdweb.snoop.log", text_only=False, no_data=False, fi=None):
        self.text_only = text_only
        self.no_data = no_data
        self.filter = fi
        self.filename = filename


class Entry:
    def __init__(self, header, summary=None, action=None, data=None):
        self.header = header
        self.summary = summary
        self.action = action
        self.data = data

    def __str__(self):
        if self.header.is_error():  # ErrorEntry
            return str(self.header)
        elif not self.summary.has_action():  # SummaryEntry
            return "{head}\n{lim}\n{sum}\n{lim}\n".format(head=self.header, lim=LIMITTER, sum=self.summary)
        elif self.action.has_data():  # DataEntry
            return "{head}\n{lim}\n{sum}\n{act}\n{data}\n{lim}\n".format(head=self.header, lim=LIMITTER, sum=self.summary, act=self.action, data=self.data)
        else:  # ActionEntry
            return "{head}\n{lim}\n{sum}\n{act}\n{lim}\n".format(head=self.header, lim=LIMITTER, sum=self.summary, act=self.action)


class SnoopParser:
    def __init__(self, config):
        self.file = open(config.filename, 'r', encoding="utf-8")
        self.header_re = re.compile(HEADER_REGEX)
        self.summary_re = re.compile(SUMMARY_REGEX)
        self.data_re = re.compile(DATA_REGEX)
        self.text_only = config.text_only
        self.no_data = config.no_data
        self.filter = config.filter

    def __iter__(self):
        return self

    def __next__(self):
        next_entry = self.parse_next_filtered()
        if next_entry is None:
            raise StopIteration
        return next_entry

    def parse_next_filtered(self) -> Entry:
        while entry := self.parse_next():
            if self.filter:
                if entry.header.thread in self.filter:
                    return entry
            else:
                return entry
        return None

    def parse_next(self) -> Entry:
        state = State.HEADER
        data = StringIO()
        while line := self.file.readline():
            line = line.strip('\n')
            match state:
                case State.HEADER:
                    if self.header_re.search(line):
                        header = fields.Header(self.header_re, line)
                        if not header.is_error():
                            state = State.OPENING_LIMIT
                        else:
                            return Entry(header)
                case State.OPENING_LIMIT:
                    if line == LIMITTER:
                        state = State.SUMMARY
                case State.SUMMARY:
                    if self.summary_re.search(line):
                        summary = fields.Summary(self.summary_re, line)
                        if summary.has_action():
                            state = State.ACTION
                        else:
                            action = None
                            state = State.CLOSING_LIMIT
                case State.ACTION:
                    action = fields.Action(line)
                    if action.has_data():
                        state = State.DATA
                    else:
                        state = State.CLOSING_LIMIT
                case State.DATA:
                    if not self.no_data and self.data_re.search(line):
                        if self.text_only:
                            line = snoop_to_text(line)
                            data.write(line)
                        else:
                            data.write(line+"\n")
                    elif not line:
                        state = State.CLOSING_LIMIT
                case State.CLOSING_LIMIT:
                    if line == LIMITTER:
                        if not self.no_data and self.text_only:
                            d = format_data(data.getvalue(), 80)
                            data = StringIO(d)
                        entry = Entry(header, summary, action, data.getvalue())
                        data = StringIO()
                        return entry
        return None
