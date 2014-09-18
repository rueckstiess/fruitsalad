#!/usr/bin/env python

from mtools.util.logfile import LogFile
from mtools.util.logevent import LogEvent
from mtools.util.cmdlinetool import LogFileTool
from random import randrange, choice

import pprint
import re
import hashlib

adjectives = ["acerbic", "acidic", "acrid", "aged", "ambrosial", "ample", "appealing", "appetizing", "aromatic", "astringent", "baked", "balsamic", "beautiful", "bite-size", "bitter", "bland", "blazed", "blended", "blunt", "boiled", "brackish", "briny", "brown", "browned", "burnt", "buttered", "caked", "candied", "caramelized", "caustic", "center-cut", "char-broiled", "cheesy", "chilled", "chocolate", "chocolate-flavored", "cholesterol-free", "chunked", "cinnamon", "classic", "classy", "clove", "coated", "cold", "cool", "copious", "country", "crafted", "creamed", "creamy", "crisp", "crunchy", "cured", "cutting", "dazzling", "deep-fried", "delicious", "delightful", "distinctive", "bivine", "doughy", "dressed", "dripping", "drizzle", "drizzled", "dry", "dulcified", "dull", "edible", "elastic", "encrusted", "ethnic", "extraordinary", "famous", "fantastic", "fetid", "fiery", "fizzy", "flaky", "flat", "flavored", "flavorful", "flavorless", "flavorsome", "fleshy", "fluffy", "fragile", "free", "free-range", "fresh", "fried", "frosty", "frozen", "fruity", "full", "full-bodied", "furry", "famy", "garlicky", "generous", "gingery", "glazed", "golden", "gorgeous", "gourmet", "greasy", "grilled", "gritty", "half", "harsh", "heady", "heaping", "heart-healthy", "hearty", "heavenly", "homemade", "honeyed", "honey-glazed", "hot", "ice-cold", "icy", "incisive", "indulgent", "infused", "insipid", "intense", "intriguing", "juicy", "jumbo", "kosher", "large", "lavish", "layered", "lean", "leathery", "lemon", "tasteful", "less", "light", "lite", "lightly-salted", "lightly-breaded", "lip-smacking", "lively", "low", "low-sodium", "low-fat", "lukewarm", "luscious", "lush", "marinated", "mashed", "mellow", "mild", "minty", "mixed", "moist", "mouth-watering", "nationally-famous", "natural", "nectarous", "non-fat", "nutmeg", "nutty", "oily", "open-face", "organic", "overpowering", "penetrating", "peppery", "perfection", "petite", "pickled", "piquant", "plain", "pleasant", "plump", "poached", "popular", "pounded", "prepared", "prickly", "pulpy", "pungent", "pureed", "rancid", "rank", "reduced", "refresh", "rich", "ripe", "roasted", "robust", "rotten", "rubbery", "saccharine", "saline", "salty", "sapid", "saporific", "saporous", "satin", "satiny", "sauteed", "savorless", "savory", "scrumptious", "seared", "seasoned", "sharp", "sharp-tasting", "silky", "simmered", "sizzling", "skillfully", "small", "smelly", "smoked", "smoky", "smooth", "smothered", "soothing", "sour", "southern-style", "special", "spiced", "spicy", "spiral-cut", "spongy", "sprinkled", "stale", "steamed", "steamy", "sticky", "stinging", "strong", "stuffed", "succulent", "sugar-coated", "sugar-free", "sugared", "sugarless", "sugary", "superb", "sweet", "sweet-and-sour", "sweetened", "syrupy", "tangy", "tantalizing", "tart", "tasteful", "tasteless", "tasty", "tender", "tepid", "terrific", "thick", "thin", "toasted", "toothsome", "topped", "tossed", "tough", "traditional", "treat", "unflavored", "unsavory", "unseasoned", "vanilla", "velvety", "vinegary", "warm", "waxy", "weak", "whipped", "whole", "wonderful", "yucky", "yummy", "zesty", "zingy"]
colors = ['aliceblue', 'antiquewhite', 'aqua', 'aquamarine', 'azure', 'beige', 'bisque', 'black', 'blanchedalmond', 'blue', 'blueviolet', 'brown', 'burlywood', 'cadetblue', 'chartreuse', 'chocolate', 'coral', 'cornflowerblue', 'cornsilk', 'crimson', 'cyan', 'darkblue', 'darkcyan', 'darkgoldenrod', 'darkgray', 'darkgreen', 'darkkhaki', 'darkmagenta', 'darkolivegreen', 'darkorange', 'darkorchid', 'darkred', 'darksalmon', 'darkseagreen', 'darkslateblue', 'darkslategray', 'darkturquoise', 'darkviolet', 'deeppink', 'deepskyblue', 'dimgray', 'dodgerblue', 'firebrick', 'floralwhite', 'forestgreen', 'fuchsia', 'gainsboro', 'ghostwhite', 'gold', 'goldenrod', 'gray', 'green', 'greenyellow', 'honeydew', 'hotpink', 'indianred', 'indigo', 'ivory', 'khaki', 'lavender', 'lavenderblush', 'lawngreen', 'lemonchiffon', 'lightblue', 'lightcoral', 'lightcyan', 'lightgoldenrodyellow', 'lightgray', 'lightgreen', 'lightpink', 'lightsalmon', 'lightseagreen', 'lightskyblue', 'lightslategray', 'lightsteelblue', 'lightyellow', 'lime', 'limegreen', 'linen', 'magenta', 'maroon', 'mediumaquamarine', 'mediumblue', 'mediumorchid', 'mediumpurple', 'mediumseagreen', 'mediumslateblue', 'mediumspringgreen', 'mediumturquoise', 'mediumvioletred', 'midnightblue', 'mintcream', 'mistyrose', 'moccasin', 'navajowhite', 'navy', 'oldlace', 'olive', 'olivedrab', 'orange', 'orangered', 'orchid', 'palegoldenrod', 'palegreen', 'paleturquoise', 'palevioletred', 'papayawhip', 'peachpuff', 'peru', 'pink', 'plum', 'powderblue', 'purple', 'red', 'rosybrown', 'royalblue', 'saddlebrown', 'salmon', 'sandybrown', 'seagreen', 'seashell', 'sienna', 'silver', 'skyblue', 'slateblue', 'slategray', 'snow', 'springgreen', 'steelblue', 'tan', 'teal', 'thistle', 'tomato', 'turquoise', 'violet', 'wheat', 'white', 'whitesmoke', 'yellow', 'yellowgreen']
fruits = ['apple', 'apricot', 'avocado', 'banana', 'breadfruit', 'bilberry', 'blackberry', 'blackcurrant', 'blueberry', 'boysenberry', 'cantaloupe', 'currant', 'cherry', 'cherimoya', 'cloudberry', 'coconut', 'cranberry', 'cucumber', 'damson', 'date', 'dragonfruit', 'durian', 'eggplant', 'elderberry', 'feijoa', 'fig', 'goji.berry', 'gooseberry', 'grape', 'raisin', 'grapefruit', 'guava', 'huckleberry', 'honeydew', 'jackfruit', 'jambul', 'jujube', 'kiwi.fruit', 'kumquat', 'lemon', 'lime', 'loquat', 'lychee', 'mango', 'marion.berry', 'melon', 'cantaloupe', 'honeydew', 'watermelon', 'rock.melon', 'miracle.fruit', 'mulberry', 'nectarine', 'nut', 'olive', 'orange', 'clementine', 'mandarine', 'blood.orange', 'tangerine', 'papaya', 'passionfruit', 'peach', 'pepper', 'chili.pepper', 'bell.pepper', 'pear', 'williams.pear.or.bartlett.pear', 'persimmon', 'physalis', 'pineapple', 'pomegranate', 'pomelo', 'mangosteen', 'quince', 'raspberry', 'western.raspberry', 'rambutan', 'redcurrant', 'salal.berry', 'salmon.berry', 'satsuma', 'star.fruit', 'strawberry', 'tamarillo', 'tomato', 'ugli.fruit', 'watermelon']

class FruitSaladTool(LogFileTool):
    """ replace IP addresses, hostnames, namespaces, strings with random values. """

    def __init__(self):
        """ Constructor: add description to argparser. """
        LogFileTool.__init__(self, multiple_logfiles=False, stdin_allowed=True)

        self.argparser.description = 'Anonymizes log files by replacing IP addresses, namespaces, strings.'
        self.replacements = {}


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
                    part = self.replacements.setdefault(part, choice(adjectives))
            
            replaced.append(part[:])

        return '.'.join(replaced)

    
    def _replace_ip(self, match):
        ip = match.group(0)
        # don't replace localhost ip
        if ip == '127.0.0.1':
            return ip

        if ip in self.replacements:
            return self.replacements[ip]
        else:
            n1 = randrange(0, 255)
            n2 = randrange(0, 255)
            return self.replacements.setdefault(ip, '192.168.%i.%i' % (n1, n2))


    def _replace_string(self, match):
        return hashlib.md5(match.group(0)).hexdigest()


    def run(self, arguments=None):
        """ Print out useful information about the log file. """
        LogFileTool.run(self, arguments)

        for logevent in self.args['logfile']:
            line = logevent.line_str

            # replace IP addresses
            line = re.sub(r'\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}', self._replace_ip, line)

            # replace strings
            line = re.sub(r'".+?"', self._replace_string, line)

            # replace hostnames and namespaces
            line = re.sub(r'[a-zA-Z$][^ \t\n\r\f\v:]+(\.[a-zA-Z$][^ \t\n\r\f\v:]+)+', self._replace_dottedname, line)

            print line


if __name__ == '__main__':
    tool = FruitSaladTool()
    tool.run()

