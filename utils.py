
from collections import OrderedDict

# Allows for dot dict access, but is also ordered (but not nested yet)
# Evil hack 1 from
#https://stackoverflow.com/questions/2352181/how-to-use-a-dot-to-access-members-of-dictionary
class OrderedAttributeDict(OrderedDict):
    __getattr__ = dict.__getitem__
    __setattr__ = dict.__setitem__
    __delattr__ = dict.__delitem__

    def __str__(self):
        s = ""
        for key, value in self.items():
            s += key + ":\n" + str(value) + "\n"
        return s[:-1]

# Allows to create ordered dicts with simple syntax
# Evil hack 2 from
#https://stackoverflow.com/questions/7878933/override-the-notation-so-i-get-an-ordereddict-instead-of-a-dict
class _OrderedDictMaker(object):
	def __getitem__(self, keys):
		if not isinstance(keys, tuple):
			keys = (keys,)
		assert all(isinstance(key, slice) for key in keys)

		return OrderedAttributeDict([(k.start, k.stop) for k in keys])

odict = _OrderedDictMaker()

# Pretty prints a dictionary
def pretty(d, indent=0):
	for key, value in d.items():
		print('\t' * indent + str(key), end="")
		if isinstance(value, dict):
			pretty(value, indent+1)
		elif isinstance(value, list):
			print("")
			for v in value:
				if isinstance(v, dict):
					pretty(v, indent+1)
				else:
					if key == "memory":
						print(str(v)+" ", end="")
					else:
						print("\t" * (indent+1) + str(v))
			if key == "memory":
				print("")
		else:
			print('\t' * (indent+1) + str(value))
