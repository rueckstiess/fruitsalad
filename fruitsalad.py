#!/usr/bin/env python

from enum import Enum
from random import seed, randrange, choice
from functools import reduce
import argparse
import re
import hashlib
import sys
import traceback
import json
import operator

adjectives = ["acerbic", "acidic", "acrid", "aged", "ambrosial", "ample", "appealing", "appetizing", "aromatic", "astringent", "baked", "balsamic", "beautiful", "bite-size", "bitter", "bland", "blazed", "blended", "blunt", "boiled", "brackish", "briny", "brown", "browned", "burnt", "buttered", "caked", "candied", "caramelized", "caustic", "center-cut", "char-broiled", "cheesy", "chilled", "chocolate", "chocolate-flavored", "cholesterol-free", "chunked", "cinnamon", "classic", "classy", "clove", "coated", "cold", "cool", "copious", "country", "crafted", "creamed", "creamy", "crisp", "crunchy", "cured", "cutting", "dazzling", "deep-fried", "delicious", "delightful", "distinctive", "bivine", "doughy", "dressed", "dripping", "drizzle", "drizzled", "dry", "dulcified", "dull", "edible", "elastic", "encrusted", "ethnic", "extraordinary", "famous", "fantastic", "fetid", "fiery", "fizzy", "flaky", "flat", "flavored", "flavorful", "flavorless", "flavorsome", "fleshy", "fluffy", "fragile", "free", "free-range", "fresh", "fried", "frosty", "frozen", "fruity", "full", "full-bodied", "furry", "famy", "garlicky", "generous", "gingery", "glazed", "golden", "gorgeous", "gourmet", "greasy", "grilled", "gritty", "half", "harsh", "heady", "heaping", "heart-healthy", "hearty", "heavenly", "homemade", "honeyed", "honey-glazed", "hot", "ice-cold", "icy", "incisive", "indulgent", "infused", "insipid", "intense", "intriguing", "juicy", "jumbo", "kosher", "large", "lavish", "layered", "lean", "leathery", "lemon", "tasteful", "less", "light", "lite", "lightly-salted",
              "lightly-breaded", "lip-smacking", "lively", "low", "low-sodium", "low-fat", "lukewarm", "luscious", "lush", "marinated", "mashed", "mellow", "mild", "minty", "mixed", "moist", "mouth-watering", "nationally-famous", "natural", "nectarous", "non-fat", "nutmeg", "nutty", "oily", "open-face", "organic", "overpowering", "penetrating", "peppery", "perfection", "petite", "pickled", "piquant", "plain", "pleasant", "plump", "poached", "popular", "pounded", "prepared", "prickly", "pulpy", "pungent", "pureed", "rancid", "rank", "reduced", "refresh", "rich", "ripe", "roasted", "robust", "rotten", "rubbery", "saccharine", "saline", "salty", "sapid", "saporific", "saporous", "satin", "satiny", "sauteed", "savorless", "savory", "scrumptious", "seared", "seasoned", "sharp", "sharp-tasting", "silky", "simmered", "sizzling", "skillfully", "small", "smelly", "smoked", "smoky", "smooth", "smothered", "soothing", "sour", "southern-style", "special", "spiced", "spicy", "spiral-cut", "spongy", "sprinkled", "stale", "steamed", "steamy", "sticky", "stinging", "strong", "stuffed", "succulent", "sugar-coated", "sugar-free", "sugared", "sugarless", "sugary", "superb", "sweet", "sweet-and-sour", "sweetened", "syrupy", "tangy", "tantalizing", "tart", "tasteful", "tasteless", "tasty", "tender", "tepid", "terrific", "thick", "thin", "toasted", "toothsome", "topped", "tossed", "tough", "traditional", "treat", "unflavored", "unsavory", "unseasoned", "vanilla", "velvety", "vinegary", "warm", "waxy", "weak", "whipped", "whole", "wonderful", "yucky", "yummy", "zesty", "zingy"]
colors = ['aliceblue', 'antiquewhite', 'aqua', 'aquamarine', 'azure', 'beige', 'bisque', 'black', 'blanchedalmond', 'blue', 'blueviolet', 'brown', 'burlywood', 'cadetblue', 'chartreuse', 'chocolate', 'coral', 'cornflowerblue', 'cornsilk', 'crimson', 'cyan', 'darkblue', 'darkcyan', 'darkgoldenrod', 'darkgray', 'darkgreen', 'darkkhaki', 'darkmagenta', 'darkolivegreen', 'darkorange', 'darkorchid', 'darkred', 'darksalmon', 'darkseagreen', 'darkslateblue', 'darkslategray', 'darkturquoise', 'darkviolet', 'deeppink', 'deepskyblue', 'dimgray', 'dodgerblue', 'firebrick', 'floralwhite', 'forestgreen', 'fuchsia', 'gainsboro', 'ghostwhite', 'gold', 'goldenrod', 'gray', 'green', 'greenyellow', 'honeydew', 'hotpink', 'indianred', 'indigo', 'ivory', 'khaki', 'lavender', 'lavenderblush', 'lawngreen', 'lemonchiffon', 'lightblue', 'lightcoral', 'lightcyan', 'lightgoldenrodyellow', 'lightgray', 'lightgreen',
          'lightpink', 'lightsalmon', 'lightseagreen', 'lightskyblue', 'lightslategray', 'lightsteelblue', 'lightyellow', 'lime', 'limegreen', 'linen', 'magenta', 'maroon', 'mediumaquamarine', 'mediumblue', 'mediumorchid', 'mediumpurple', 'mediumseagreen', 'mediumslateblue', 'mediumspringgreen', 'mediumturquoise', 'mediumvioletred', 'midnightblue', 'mintcream', 'mistyrose', 'moccasin', 'navajowhite', 'navy', 'oldlace', 'olive', 'olivedrab', 'orange', 'orangered', 'orchid', 'palegoldenrod', 'palegreen', 'paleturquoise', 'palevioletred', 'papayawhip', 'peachpuff', 'peru', 'pink', 'plum', 'powderblue', 'purple', 'red', 'rosybrown', 'royalblue', 'saddlebrown', 'salmon', 'sandybrown', 'seagreen', 'seashell', 'sienna', 'silver', 'skyblue', 'slateblue', 'slategray', 'snow', 'springgreen', 'steelblue', 'tan', 'teal', 'thistle', 'tomato', 'turquoise', 'violet', 'wheat', 'white', 'whitesmoke', 'yellow', 'yellowgreen']
fruits = ['apple', 'apricot', 'avocado', 'banana', 'breadfruit', 'bilberry', 'blackberry', 'blackcurrant', 'blueberry', 'boysenberry', 'cantaloupe', 'currant', 'cherry', 'cherimoya', 'cloudberry', 'coconut', 'cranberry', 'cucumber', 'damson', 'date', 'dragonfruit', 'durian', 'eggplant', 'elderberry', 'feijoa', 'fig', 'goji.berry', 'gooseberry', 'grape', 'raisin', 'grapefruit', 'guava', 'huckleberry', 'honeydew', 'jackfruit', 'jambul', 'jujube', 'kiwi.fruit', 'kumquat', 'lemon', 'lime', 'loquat', 'lychee', 'mango', 'marion.berry', 'melon', 'cantaloupe',
          'honeydew', 'watermelon', 'rock.melon', 'miracle.fruit', 'mulberry', 'nectarine', 'nut', 'olive', 'orange', 'clementine', 'mandarine', 'blood.orange', 'tangerine', 'papaya', 'passionfruit', 'peach', 'pepper', 'chili.pepper', 'bell.pepper', 'pear', 'williams.pear.or.bartlett.pear', 'persimmon', 'physalis', 'pineapple', 'pomegranate', 'pomelo', 'mangosteen', 'quince', 'raspberry', 'western.raspberry', 'rambutan', 'redcurrant', 'salal.berry', 'salmon.berry', 'satsuma', 'star.fruit', 'strawberry', 'tamarillo', 'tomato', 'ugli.fruit', 'watermelon']


class LogType(Enum):
    TEXT = 0
    JSON = 1


class FruitSaladTool():
    """ replace IP addresses, hostnames, namespaces, strings with random values. """

    def __init__(self, arg_logfile, arg_seed=None):
        self.seed = str(arg_seed)
        self.logfile = arg_logfile
        self.replacements = {}
        self.logtype = self._get_logtype()


    def _replace_dottedname(self, match):
        parts = match.group(0).split('.')
        replaced = []
        for i, part in enumerate(parts):
            if i == 0 and part in ['system', 'local', 'admin', 'config']:
                return '.'.join(parts)

            if part not in ['$cmd', 'com', 'net', 'org', 'edu', 'gov']:
                if i == len(parts) - 1:
                    part = self.replacements.setdefault(part, choice(fruits))
                elif i == len(parts) - 2:
                    part = self.replacements.setdefault(part, choice(colors))
                else:
                    part = self.replacements.setdefault(
                        part, choice(adjectives))

            replaced.append(part[:])

        return '.'.join(replaced)


    def _replace_ip(self, match):
        ip = match.group(2)
        # don't replace localhost ip
        if ip == '127.0.0.1':
            return match.group(1) + ip + match.group(3)

        if ip in self.replacements:
            return match.group(1) + \
                self.replacements[ip] + \
                match.group(3)
        else:
            n1 = randrange(0, 255)
            n2 = randrange(0, 255)
            return match.group(1) + \
                self.replacements.setdefault(ip, '192.168.%i.%i' % (n1, n2)) + \
                match.group(3)


    def _replace_namespace(self, match):
        ns_type = match.group(1)
        ns = match.group(2)
        parts = ns.split('.')
        replaced = []
        for i, part in enumerate(parts):
            if i == 0 and part in ['system', 'local', 'admin', 'config'] or part in ['$cmd']:
                replaced.append(part[:])
                continue

            if i == len(parts) - 1:
                part = self.replacements.setdefault(part, choice(fruits))
            elif i == len(parts) - 2:
                part = self.replacements.setdefault(part, choice(colors))
            else:
                part = self.replacements.setdefault(part, choice(adjectives))

            replaced.append(part[:])

        return '"' + ns_type + '":"' + '.'.join(replaced) + '"'


    def _replace_string(self, match):
        return '"' + hashlib.md5(str(match.group(0)).encode('utf-8')).hexdigest() + '"'


    def _obfuscate_user(self, data, path):
        user = self._get_by_path(data, path)
        if user is None or user in ['__system']:
            return
        user = self.replacements.setdefault(user, choice(fruits))
        self._set_by_path(data, path, user)

    def _obfuscate_namespace(self, data, path):
        ns = self._get_by_path(data, path)
        if ns is None:
            return
        # Dont obfuscate well known system namespaces
        if ns in ['local.oplog.rs', 'oplog.rs']:
            return ns
        parts = ns.split('.')
        replaced = []
        for i, part in enumerate(parts):
            if i == 0 and part in ['system', 'local', 'admin', 'config'] or part in ['$cmd']:
                replaced.append(part[:])
                continue

            if i == len(parts) - 1:
                part = self.replacements.setdefault(part, choice(fruits))
            elif i == len(parts) - 2:
                part = self.replacements.setdefault(part, choice(colors))
            else:
                part = self.replacements.setdefault(part, choice(adjectives))

            replaced.append(part[:])
        self._set_by_path(data, path, '.'.join(replaced))


    def _obfuscate_command(self, data, path):
        obj = self._get_by_path(data, path)
        if obj is None:
            return
        if obj == {}:
            return {}
        command = json.dumps(obj)
        hash = self.replacements.setdefault(
            command, hashlib.md5(command.encode('utf-8')).hexdigest())
        self._set_by_path(data, path, hash)


    def _obfuscate_plan(self, match):
        ns = re.sub(r'([^\s]+):',
                    lambda x: self.replacements.setdefault(
                        x[1], choice(fruits)) + ':',
                    match[2])
        return match[1] + ' ' + ns


    def _obfuscate_planSummary(self, data):
        planSummary = self._get_by_path(data, "attr.planSummary")
        if planSummary is None:
            return
        plan = json.dumps(planSummary).strip('"')
        obfuscated_plan = re.sub(r'(\w+) ({[^}]+},?)',
                                 self._obfuscate_plan, plan)
        self._set_by_path(data, "attr.planSummary", obfuscated_plan)

    def _obfuscate_keys(self, data, path):
        obj = self._get_by_path(data, path)
        if obj is None:
            return
        doc = {}
        for key in obj:
            doc[self.replacements.setdefault(key, choice(fruits))] = obj[key]
        self._set_by_path(data, path, doc)


    def _obfuscate_truncation(self, data):
        obj = self._get_by_path(data, "truncated")
        if obj is None:
            return
        for key in obj.keys():
            for subkey in obj.get(key, {}):
                self._obfuscate_command(
                    data, "truncated." + key + '.' + subkey)


    def _obfuscate_stats(self, data):
        path = "attr.stats.inputStage.inputStages"
        obj = self._get_by_path(data, path)
        if obj is None:
            print('none')
            return
        for stage in obj:
            if stage == {}:
                continue
            for val in ["filter", "keyPattern", "indexName", "multiKeyPaths", "indexBounds"]:
                if val not in stage:
                    continue
                raw = json.dumps(stage[val])
                stage[val] = self.replacements.setdefault(
                    raw, hashlib.md5(raw.encode('utf-8')).hexdigest())
        self._set_by_path(data, path, obj)
    

    def run(self):
        """ Print out useful information about the log file. """

        if self.seed != None:
            seed(self.seed)
        line_counter = 0
        for logevent in open(self.logfile, 'r'):
            line = logevent

            # replace IP addresses, ignore version strings
            line = re.sub(r'([^\w])(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})([^\w])',
                          self._replace_ip, line)

            if self.logtype == LogType.TEXT:
                # replace strings
                line = re.sub(r'".+?"', self._replace_string, line)

                # replace hostnames and namespaces
                line = re.sub(
                    r'[a-zA-Z$][^ \t\n\r\f\v:\'"]+(\.[a-zA-Z$][^ \t\n\r\f\v:\'"]+)+',
                    self._replace_dottedname, line)
                sys.stdout.write(line.rstrip() + '\n')

            elif self.logtype == LogType.JSON:
                try:
                    line_counter = line_counter + 1
                    loaded_line = json.loads(line)
                except json.decoder.JSONDecodeError as e:
                    if re.match(r'^\s*$', line):
                        continue
                    sys.stderr.write('Error reading line ' +
                                     str(line_counter) + ' from ' + self.logfile + '\n\n')
                    traceback.print_exc()
                    sys.stderr.write('\nRaw JSON:\n')
                    sys.stderr.write(line + '\n')
                    sys.exit()

                try:
                    # PII is only found in .attr
                    if "attr" not in loaded_line:
                        print(json.dumps(loaded_line))
                        continue

                    if "truncated" in loaded_line:
                        self._obfuscate_truncation(loaded_line)

                    self._obfuscate_command(loaded_line, "attr.reason")
                    self._obfuscate_command(loaded_line, "attr.indexName")

                    self._obfuscate_namespace(
                        loaded_line, "attr.authenticationDatabase")
                    self._obfuscate_user(
                        loaded_line, "attr.principalName")

                    self._obfuscate_namespace(
                        loaded_line, "attr.namespace")
                    self._obfuscate_namespace(
                        loaded_line, "attr.sourceNamespace")
                    self._obfuscate_namespace(
                        loaded_line, "attr.targetNamespace")

                    self._obfuscate_namespace(loaded_line, "attr.ns")
                    self._obfuscate_namespace(loaded_line, "attr.fromName")
                    self._obfuscate_namespace(loaded_line, "attr.toName")
                    self._obfuscate_namespace(loaded_line, "attr.command.$db")

                    self._obfuscate_command(
                        loaded_line, "attr.command.q")
                    self._obfuscate_command(
                        loaded_line, "attr.command.u")
                    self._obfuscate_command(
                        loaded_line, "attr.command.pipeline")
                    self._obfuscate_command(
                        loaded_line, "attr.command.filter")
                    self._obfuscate_command(
                        loaded_line, "attr.command.query")

                    self._obfuscate_command(
                        loaded_line, "attr.error.errmsg")

                    self._obfuscate_namespace(
                        loaded_line, "attr.command.aggregate")
                    self._obfuscate_namespace(
                        loaded_line, "attr.command.find")
                    self._obfuscate_namespace(
                        loaded_line, "attr.command.update")
                    self._obfuscate_namespace(
                        loaded_line, "attr.command.insert")
                    self._obfuscate_namespace(
                        loaded_line, "attr.command.delete")

                    self._obfuscate_namespace(
                        loaded_line, "attr.command.killCursors")
                    self._obfuscate_namespace(
                        loaded_line, "attr.command.collection")

                    self._obfuscate_keys(
                        loaded_line, "attr.command.sort")

                    self._obfuscate_planSummary(loaded_line)

                    self._obfuscate_namespace(loaded_line, "attr.CRUD.ns")
                    self._obfuscate_command(loaded_line, "attr.CRUD.o")

                    if loaded_line.get('attr', {}).get('originatingCommand', None) is not None:
                        self._obfuscate_namespace(
                            loaded_line, "attr.originatingCommand.find")
                        self._obfuscate_command(
                            loaded_line, "attr.originatingCommand.aggregate")
                        self._obfuscate_namespace(
                            loaded_line, "attr.originatingCommand.$db")
                        self._obfuscate_command(
                            loaded_line, "attr.originatingCommand.filter")
                        self._obfuscate_command(
                            loaded_line, "attr.originatingCommand.projection")

                    if loaded_line.get('attr', {}).get('stats', None) is not None:
                        self._obfuscate_stats(loaded_line)

                except Exception:
                    sys.stderr.write('Error processing line ' +
                                     str(line_counter) + ' from ' + self.logfile + '\n\n')
                    traceback.print_exc()
                    sys.stderr.write('\nRaw JSON:\n')
                    sys.stderr.write(line + '\n')
                    sys.exit()

                print(json.dumps(loaded_line))


    def _get_logtype(self):
        with open(self.logfile, 'r') as f:
            line = f.readline()
            if line[0] == '{':
                return LogType.JSON
            else:
                return LogType.TEXT

    def _get_by_path(self, data, path):
        if isinstance(path, str):
            keys = path.split('.')
        elif isinstance(path, list):
            keys = path
        else:
            raise Exception(
                '_get_by_path expects str or list for path argument')
        try:
            return reduce(operator.getitem, keys, data)
        except Exception as e:
            return None


    def _set_by_path(self, data, path, value):
        keys = path.split('.')
        obj = self._get_by_path(data, keys[:-1])
        if not isinstance(obj, dict):
            return
        obj[keys[-1]] = value


if __name__ == '__main__':
    argparser = argparse.ArgumentParser()
    argparser.description = 'Anonymizes log files by replacing IP addresses, namespaces, strings.'
    argparser.add_argument('--seed', '-s', action='store', metavar='S',
                           default=None, help='seed the random number generator with S (any string)')
    argparser.add_argument('logfile', type=str)
    args = argparser.parse_args()

    tool = FruitSaladTool(arg_seed=args.seed, arg_logfile=args.logfile)
    tool.run()
