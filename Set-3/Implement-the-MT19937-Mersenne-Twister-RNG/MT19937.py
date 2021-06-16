class MT19937:
	__w, __n, __n, __r = 32, 624, 397, 31
	__a = 0x9908B0DF
	__u, __d = 11, 0xFFFFFFFF
	__s, __b = 7, 0x9D2C5680
	__t, __c = 15, 0xEFC60000
	__l = 18
	__f = 1812433253

	def __init__(self, seed: int):
		self.__MT = [0] * self.__n
		self.__MT[0] = seed
		for i in range(1, self.__n):
			self.__MT[i] = self.__f * (self.__MT[i - 1] ^ (self.__MT[i - 1] >> (self.__w - 2))) + i
		self.index = self.__n + 1
	
	def __twist(self):
		for i in range(self.__n):
			pass

	def extract_number(self):
		pass
