import logging
import codecs
import yaml
import re


logger = logging.getLogger(__name__)


class Patterns:

    _translate = {
        "base64": lambda p: codecs.decode(p.encode(), 'base64'),
        "python": lambda p: codecs.decode(p.encode(), 'unicode_escape').encode(),
        "regexp": lambda p: re.compile(p.encode()),
        "plain" : lambda p: codecs.encode(p, 'utf8'),
        "hex"   : lambda p: codecs.decode(p.encode(), "hex"),
    }

    def __init__(self, filename):
        self.filename = filename
        self.config = {}

        self.plain_patterns = set()
        self.re_patterns = set()
        self.max_len = 0

        if filename:
            self.load()

    def load(self):
        with open(self.filename, 'r') as configfile:
            config = yaml.load(configfile)

        patterns = config.get("patterns", {})

        for key in patterns:
            if key not in self._translate:
                logger.warning("Unknown encoding: %s", key)
                continue

            for pattern in patterns[key]:
                try:
                    pattern = self._translate[key](pattern)
                except Exception as e:
                    logger.warning(e)
                    continue

                if key == 'regexp':
                    self.max_len = max(self.max_len, len(pattern.pattern))
                    self.re_patterns.add(pattern)
                else:
                    self.max_len = max(self.max_len, len(pattern))
                    self.plain_patterns.add(pattern)

        conf = config.get("conf", {})
        max_len = conf.get("max_len", "auto")

        if max_len != "auto":
            self.max_len = max(self.max_len, int(max_len))

    def has_patterns(self):
        return not self.filename or self.plain_patterns or self.re_patterns

    def find(self, chunk, pos, endpos):
        for pattern in self.plain_patterns:
            if chunk.find(pattern, pos, endpos) != -1:
                return pattern

        for pattern in self.re_patterns:
            needle = pattern.search(chunk, pos, endpos)

            if needle:
                return needle

        return False
