import re
from enum import Enum
from enum import auto
from io import StringIO
import textwrap
import fields

HEADER_REGEX = r"(?P<date>\d\d\d\d-\d\d-\d\d-\d\d:\d\d:\d\d.\d\d\d\+\d\d:\d\d)I----- thread\((?P<thread>\d\d)\) (?P<component>.+) (?P<file>.+:\d+:)(?P<remainder>.*)"
SUMMARY_REGEX = r"Thread (?P<thread>\d+); fd (?P<fd>\d+); local (?P<local>.+); remote (?P<remote>.+)"
DATA_REGEX = r"^0x[a-zA-Z0-9]{4}"
LIMITTER = "----------------------------------------"
START_OF_TEXT = 56


class State(Enum):
    Header = auto()
    OpeningLimit = auto()
    Summary = auto()
    Action = auto()
    Data = auto()
    ClosingLimit = auto()


def snoop_to_text(line) -> str:
    return line[START_OF_TEXT:]


def format_data(data, length):
    return "\n".join(list((data[0+i:length+i] for i in range(0, len(data), length))))


class SnoopConfig:
    def __init__(self, filename="pdweb.snoop.log", text_only=False, no_data=False, filter=None):
        self.text_only = text_only
        self.no_data = no_data
        self.filter = filter
        self.filename = filename


class Entry:
    def __init__(self, header, summary=None, action=None, data=None):
        self.header = header
        self.summary = summary
        self.action = action
        self.data = data

    def __str__(self):
        if self.header.is_error():  # ErrorEntry
            return "{}".format(self.header)
        elif self.action.has_data():  # DataEntry
            return "{}\n{}\n{}\n{}\n{}\n{}\n".format(self.header, LIMITTER, self.summary, self.action, self.data, LIMITTER)
        else:  # ActionEntry
            return "{}\n{}\n{}\n{}\n{}\n".format(self.header, LIMITTER, self.summary, self.action, LIMITTER)


class SnoopParser:
    def __init__(self, config):
        self.file = open(config.filename, 'r')
        self.header_re = re.compile(HEADER_REGEX)
        self.summary_re = re.compile(SUMMARY_REGEX)
        self.data_re = re.compile(DATA_REGEX)
        self.text_only = config.text_only
        self.no_data = config.no_data
        self.filter = config.filter

    def __iter__(self):
        return self

    def __next__(self):
        next = self.parse_next_filtered()
        if next == None:
            raise StopIteration
        return next

    def parse_next_filtered(self) -> Entry:
        while entry := self.parse_next():
            if self.filter:
                x = self.filter
                y = entry.header.thread
                if entry.header.thread in self.filter:
                    return entry
            else:
                return entry
        return None

    def parse_next(self) -> Entry:
        state = State.Header
        data = StringIO()
        while line := self.file.readline():
            line = line.strip('\n')
            match state:
                case State.Header:
                    if self.header_re.search(line):
                        header = fields.Header(self.header_re, line)
                        if not header.is_error():
                            state = State.OpeningLimit
                        else:
                            return Entry(header)
                case State.OpeningLimit:
                    if line == LIMITTER:
                        state = State.Summary
                case State.Summary:
                    if self.summary_re.search(line):
                        summary = fields.Summary(self.summary_re, line)
                        state = State.Action
                case State.Action:
                    action = fields.Action(line)
                    if action.has_data():
                        state = State.Data
                    else:
                        state = State.ClosingLimit
                case State.Data:
                    if not self.no_data and self.data_re.search(line):
                        if self.text_only:
                            line = snoop_to_text(line)
                            data.write(line)
                        else:
                            data.write("{}\n".format(line))
                    elif not line:
                        state = State.ClosingLimit
                case State.ClosingLimit:
                    if line == LIMITTER:
                        if not self.no_data and self.text_only:
                            d = format_data(data.getvalue(), 80)
                            data = StringIO(d)
                        entry = Entry(header, summary, action, data.getvalue())
                        data = StringIO()
                        return entry
        return None
