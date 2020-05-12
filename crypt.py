import os
import argparse

from Crypto.Cipher import AES
from Crypto.Util.Padding import pad


def get_arguments():
	parser = argparse.ArgumentParser(description='AES CBC encryption of files.')
	parser.add_argument('-o', '--object_path', required=True, help='Path to object for encryption.')
	parser.add_argument('-k', '--key', required=True, help='Key for encryption (MAX: 32 letters).')
	parser.add_argument('-d', '--decryption', action='store_true', help='Decryption mode.')
	parser.add_argument('-p', '--path_to_copy', default='(Replace object)', help='Path to copy object.')
	return parser.parse_args()


class Crypt:
	def __init__(self, args):
		self.__encrypted_marker = b'[ENCRYPTED]'
		self.__empty_byte = b'\x00'
		self.__block_size = 16
		self.__key = self.__enc_pad(args.key.encode())
		self.__iv = self.__key[:16]
		self.__object_path = args.object_path
		if not args.decryption:
			self.__mode = 'encryption'
		else:
			self.__mode = 'decryption'
		if args.path_to_copy == '(Replace object)':
			self.__new_object_path = self.__object_path
		else:
			self.__new_object_path = args.path_to_copy


	def __enc_pad(self, data):
		data_size = len(data)
		amount_pad = 0
		if data_size % self.__block_size:
			amount_pad = self.__block_size - data_size % self.__block_size
		data = data + bytearray(amount_pad)
		return data


	def __unpad(self, enc_padded_data):
		return enc_padded_data.rstrip(self.__empty_byte)


	def __encrypt(self, enc_padded_data):
		cipher = AES.new(self.__key, AES.MODE_CBC, self.__iv)
		encrypted_data = cipher.encrypt(enc_padded_data)
		return encrypted_data


	def __decrypt(self, encrypted_data):
		iv = self.__key[:16]
		cipher = AES.new(self.__key, AES.MODE_CBC, iv)
		decryted_data = cipher.decrypt(encrypted_data)
		return decryted_data


	def __check_object(self, object_path):
		if not os.path.exists(object_path):
			exit('Object not found.')
		else:
			if os.path.isdir(object_path):
				return 'dir'
			else:
				return 'file'


	def __get_file_content(self, object_path):
		with open(object_path, 'rb') as file:
			data = file.read()
			file.close()
		return data


	def __create_file(self, object_path, data):
		with open(object_path, 'wb') as file:
			file.write(data)
			file.close()


	def __encrypt_dir(self, object_path):
		count_files = 0
		errors = []
		for root, dirs, files in os.walk(object_path):
			for file in files:

				path = root + '\\' + file
				content = self.__get_file_content(path)
	
				if content.startswith(self.__encrypted_marker):
					errors.append((path, 'already encrypted.'))
					continue

				padded_data = self.__enc_pad(content)
				encrypted_data = self.__encrypted_marker + self.__encrypt(padded_data)
				
				# if need new dictionary
				if self.__object_path != self.__new_object_path:	
					path = path.replace(object_path, self.__new_object_path)

					if not os.path.exists(os.path.dirname(path)):
						os.makedirs(os.path.dirname(path))
					
				self.__create_file(path, encrypted_data)
				count_files += 1

		if errors:
			if count_files == len(errors):
				print('All files in directory already encrypted.')
			else:
				for path, error in errors:
					print(path, error)
		else:
			print(self.__object_path, 'has been successfully encrypted.')
		

	def __decrypt_dir(self, object_path):
		count_files = 0
		errors = []
		for root, dirs, files in os.walk(object_path):
			for file in files:
	
				path = root + '\\' + file
				content = self.__get_file_content(path)

				if not content.startswith(self.__encrypted_marker):
					errors.append((path, 'is not encrypted.'))
					continue

				decrypted_data = self.__decrypt(content[len(self.__encrypted_marker):])
				unpadded_data = self.__unpad(decrypted_data)
				
				# if need new dictionary
				if self.__object_path != self.__new_object_path:	
					path = path.replace(object_path, self.__new_object_path)

					if not os.path.exists(os.path.dirname(path)):
						os.makedirs(os.path.dirname(path))

				self.__create_file(path, unpadded_data)
				count_files += 1

		if errors:
			if count_files == len(errors):
				print('All files in directory already decrypted.')
			else:
				for path, error in errors:
					print(path, error)
		else:
			print(self.__object_path, 'has been successfully decrypted.')


	def __encrypt_file(self, object_name):
		data = self.__get_file_content(object_name)
		if data.startswith(self.__encrypted_marker):
			exit(object_name + ' already encrypted.')
		padded_data = self.__enc_pad(data)
		encrypted_data = self.__encrypted_marker + self.__encrypt(padded_data)
		self.__create_file(self.__new_object_path, encrypted_data)
		if self.__object_path == self.__new_object_path:
			print(self.__object_path, 'has been successfully encrypted.')
		else:
			print(self.__object_path, '[decrypted] ->', self.__new_object_path, '[encrypted].')


	def __decrypt_file(self, object_name):
		data = self.__get_file_content(object_name)
		if not data.startswith(self.__encrypted_marker):
			exit(object_name + ' is not encrypted.')
		decrypted_data = self.__decrypt(data[len(self.__encrypted_marker):])
		unpadded_data = self.__unpad(decrypted_data)
		self.__create_file(self.__new_object_path, unpadded_data)
		if self.__object_path == self.__new_object_path:
			print(self.__object_path, 'has been successfully decrypted.')
		else:
			print(self.__object_path, '[encrypted] ->', self.__new_object_path, '[decrypted].')


	def run(self):
		if self.__check_object(self.__object_path) == 'dir':
			if self.__mode == 'encryption':
				self.__encrypt_dir(self.__object_path)
			else:
				self.__decrypt_dir(self.__object_path)
		else:
			if self.__mode == 'encryption':
				self.__encrypt_file(self.__object_path)
			else:
				self.__decrypt_file(self.__object_path)


if __name__ == '__main__':
	Crypt(get_arguments()).run()
