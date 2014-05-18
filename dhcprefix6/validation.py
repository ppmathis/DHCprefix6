import functools


class ArgumentValidationError(ValueError):
	def __init__(self, arg_num, func_name, accepted_arg_type):
		self.error = 'The {0} argument of {1}() is not a {2}'.format(arg_num, func_name, accepted_arg_type)

	def __str__(self):
		return self.error


class InvalidArgumentNumberError(ValueError):
	def __init__(self, func_name):
		self.error = 'Invalid number of arguments for {0}()'.format(func_name)

	def __str__(self):
		return self.error


class InvalidReturnType(ValueError):
	def __init__(self, return_type, func_name):
		self.error = 'Invalid return type {0} for {1}()'.format(return_type, func_name)

	def __str__(self):
		return self.error


def _ordinal(num):
	if 10 <= num % 100 < 20:
		return '{0}th'.format(num)
	else:
		ordnum = {1: 'st', 2: 'nd', 3: 'rd'}.get(num % 10, 'th')
		return '{0}{1}'.format(num, ordnum)


def accepts(*accepted_arg_types):
	def accept_decorator(validate_function):
		@functools.wraps(validate_function)
		def decorator_wrapper(*function_args, **function_args_dict):
			if len(accepted_arg_types) is not len(accepted_arg_types):
				raise InvalidArgumentNumberError(validate_function.__name__)

			for arg_num, (actual_arg, accepted_arg_type) in enumerate(zip(function_args, accepted_arg_types)):
				if accepted_arg_type is not object and type(actual_arg) is not accepted_arg_type:
					ord_num = _ordinal(arg_num + 1)
					raise ArgumentValidationError(ord_num, validate_function.__name__, accepted_arg_type)

			return validate_function(*function_args)

		return decorator_wrapper

	return accept_decorator


def returns(*accepted_return_type_tuple):
	def return_decorator(validate_function):
		if len(accepted_return_type_tuple) == 0:
			raise TypeError('You must specify a return type.')

		@functools.wraps(validate_function)
		def decorator_wrapper(*function_args):
			if len(accepted_return_type_tuple) > 1:
				raise TypeError('You must specify one return type.')

			accepted_return_type = accepted_return_type_tuple[0]
			return_value = validate_function(*function_args)
			return_value_type = type(return_value)

			if return_value_type is not accepted_return_type:
				raise InvalidReturnType(return_value_type, validate_function.__name__)

			return return_value

		return decorator_wrapper

	return return_decorator


class ValidatedType(object):
	_value = None

	def __init__(self, value):
		self.value = value

	def __str__(self):
		return str(self.value)

	def __int__(self):
		return int(self.value)

	def __repr__(self):
		return "%s(%r)" % (self.__class__.__name__, self.value)

	def __eq__(self, other):
		return self.value == other.value

	@staticmethod
	def validate(value):
		return True

	@property
	def value(self):
		return self._value

	@value.setter
	def value(self, value):
		if not self.validate(value):
			raise ValueError("Invalid value provided for type %s" % self.__class__.__name__)
		self._value = value