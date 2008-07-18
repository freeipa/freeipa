class Command(object):
	def normalize(self, kw):
		raise NotImplementedError

	def validate(self, kw):
		raise NotImplementedError

	def execute(self, kw):
		raise NotImplementedError

	def __call__(self, **kw):
		kw = self.normalize(kw)
		invalid = self.validate(kw)
		if invalid:
			return invalid
		return self.execute(kw)



class Argument(object):
	pass


class NameSpace(object):
	def __init__(self):
		pass




class API(object):
	def __init__(self):
		self.__c = object()
		self.__o = object()

	def __get_c(self):
		return self.__c
	c = property(__get_c)

	def __get_o(self):
		return self.__o
	o = property(__get_o)

	def register_command(self, name, callback, override=False):
		pass
