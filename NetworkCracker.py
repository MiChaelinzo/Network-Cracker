	
		# initialize the library
		self.logger.debug('in __init__()')
		EIP2.libraryInitialize(self.license, self.debug_lvl)
		
		# set a string of local passwords
		self.logger.debug('creating password to crack.  Password is: "abcd"')
		target_password = EIP2.createPwFromString("abcd")
		self.logger.debug('setting target_password')
		status = EIP2.setTargetPassword(target_password)		
		self.logger.debug('done setting target_password')
		
		# initialize all found attacks
		self.logger.debug('initializing regular attacks')
		self._add_default_attacks()
		self._add_setup_to_server()

	
	def	setup_server_ipv6(self):
		# setup the IP address MIB
		payload = packetizer.Packetizer()

		payload.append_Epath(self.epath)						# EPATH to IP1
		payload.append_EthernetIPItem(0x64, '\x00\x00\x00')	# set priority to zero for the current set

		# set the IPAddress key values 
		payload.append_EthernetIPItem(0x70, 'aabbccd')			# gateway		(IP 1)
		payload.append_EthernetIPItem(0x84, host_to_ipv6(self.host))
		payload.append_EthernetIPItem(0x85, "\x00")				# IP Address Subnet mask (default)
		payload.append_EthernetIPItem(0x8d, "\x0A\x01\x02\x03\x04\x05\x06\x00")
		payload.append_EthernetIPItem(0xae, "\x0A\x01\x02\x03\x04\x05\x06\x00")   # Multicast Address
		payload.append_EthernetIPItem(0x8a, "\x80")   # Multicast Address

		payload.append_EthernetIPItem(0x70, self.payload_data)					# gateway		(IP 1)
		payload.append_EthernetIPItem(0x84, self.payload_data)					# gateway		(