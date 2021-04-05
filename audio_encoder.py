from scipy.io.wavfile import read, write
from time import sleep
import io, hashlib, os, random
import numpy as np

BITS=8 #length of each symbol in bits
TIME_SYM=['0','1','2','3','4','5','6','7','8','9',' ','-',':','.']
MARK_LEN=len(TIME_SYM)
HASH_SYM=('0','1','2','3','4','5','6','7','8','9','a','b','c','d','e','f','g','h','i','j','k','l','m','n','o','p','q','r','s','t','u','v','w','x','y','z',)
HASH=''
KEY_LEN=len(hashlib.sha512(b'Hello World').hexdigest())
HASH_FUNC='SHA512'
HASH_FUNCTIONS=('SHA1',
				'SHA3_224',
				'SHA3_256',
				'SHA3_384',
				'SHA3_512',
				'SHA224',
				'SHA256',
				'SHA384',
				'SHA512',
				'MD5',
				'BLAKE2b',
				'BLAKE2s',)

def clear():
	#clear
	os.system('cls' if os.name == 'nt' else 'clear')


def to_bin(sym):
	res=''
	while sym>0:
		res=str(sym%2)+res
		sym//=2

	while len(res)<BITS:
		res='0'+res

	return res


def to_dec(sym):
	res=0
	i=0
	while len(sym)>0:
		res+=int(sym[len(sym)-1:])*(2**int(i))
		i+=1
		sym=sym[:-1]
	return res


def make_dic(mes):
	global HASH
	j=0
	dic={}
	for i in range(len(mes)):
		if mes[i] not in dic.keys():
			while True:
				temp=ord(mes[i])
				temp+=ord(HASH[j])
				if temp>2**BITS:
					t_bits=BITS
					while temp>2**t_bits:
						t_bits+=1
					print('Symbol:',mes[i],'has too big code! Make encoding depth greater than',(t_bits-1))
					return -1
				t=to_bin(temp)
				if t not in dic.values():
					dic[mes[i]]=t
					j+=1
					break
				else:
					if j == len(HASH):
						HASH+=random.choice('abcdefghijklmnopqrstuvwxyz0123456789')
					temp=ord(HASH[j])+1
					temp=chr(temp)
					st=HASH[:j]
					fn=HASH[j+1:]
					HASH=st+temp+fn
	return dic


def get_dic(mes):
	try:
		dic={}
		j=0
		for i in range(len(mes)//BITS):
			byte=mes[:BITS]
			mes=mes[BITS:]
			if byte not in dic.keys():
				value=to_dec(byte)-ord(HASH[j])
				j+=1
				sym=chr(value)
				dic[byte]=sym
		return dic
	except:
		return -1


def hashing(name,string):
	if name=='SHA1':
		return hashlib.sha1(string.encode('utf-8')).hexdigest()
	elif name=='SHA3_224':
		return hashlib.sha3_224(string.encode('utf-8')).hexdigest()
	elif name=='SHA3_256':
		return hashlib.sha3_256(string.encode('utf-8')).hexdigest()
	elif name=='SHA3_384':
		return hashlib.sha3_384(string.encode('utf-8')).hexdigest()
	elif name=='SHA3_512':
		return hashlib.sha3_512(string.encode('utf-8')).hexdigest()
	elif name=='SHA224':
		return hashlib.sha224(string.encode('utf-8')).hexdigest()
	elif name=='SHA256':
		return hashlib.sha256(string.encode('utf-8')).hexdigest()
	elif name=='SHA384':
		return hashlib.sha384(string.encode('utf-8')).hexdigest()
	elif name=='SHA512':
		return hashlib.sha512(string.encode('utf-8')).hexdigest()
	elif name=='MD5':
		return hashlib.md5(string.encode('utf-8')).hexdigest()
	elif name=='BLAKE2b':
		return hashlib.blake2b(string.encode('utf-8')).hexdigest()
	elif name=='BLAKE2s':
		return hashlib.blake2s(string.encode('utf-8')).hexdigest()


def fromWav(file):
	with open(file, 'rb') as wavfile:
	    input_wav = wavfile.read()
	rate, data = read(io.BytesIO(input_wav))
	copy= data.copy()
	copy.setflags(write=1)	
	return rate, copy


def toWav(file, rate, data):
	bytes_wav = bytes()
	byte_io = io.BytesIO(bytes_wav)
	write(byte_io, rate, data)
	
	output_wav = byte_io.read()
	f=open(file,'wb')
	f.write(output_wav)
	f.close()



def encode(source, result, mes):
	global HASH, TIME_SYM
	
	t_len = random.randint(5,50)
	key=''
	while len(key)<t_len:
		key+=random.choice('abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789`!@#$%^&*()_+')
	HASH=hashing(HASH_FUNC,key)

	rate,arr = fromWav(source)
	
	temp=''
	for i in TIME_SYM:
		temp+=i
	dic=make_dic(temp+mes)
	if dic==-1:
		return -1

	mes=temp+mes+temp

	new=''
	for item in mes:
		new+=dic[item]
	mes=new
	
	if len(arr)<len(mes):
		print('Message is too long!')
		return -1
	
	print('Working...')

	for i in range(len(arr)):
		e=arr[i]
		f,s=e[0],e[1]
		f=to_bin(f)
		s=to_bin(s)
		if len(mes)>0:
			lf=mes[0]
			mes=mes[1:]
			f=f[:-1]+lf
			f=to_dec(f)
			s=to_dec(s)
			arr[i][0]=int(f)
			arr[i][1]=int(s)
		else:
			break
		if len(mes)>0:
			s=to_bin(s)
			ls=mes[0]
			mes=mes[1:]
			s=s[:-1]+ls
			s=to_dec(s)
			arr[i][0]=int(f)
			arr[i][1]=int(s)
		else:
			break
		
	toWav(result,rate,arr)
	print('Done!')
	print('Secret Key:',HASH)

def decode(source):
	global HASH
	while True:
		key=str(input('Secret Key: '))
		if len(key)==0:
			print('Input a Key!')
		elif len(key)<KEY_LEN:
			print('The length must be greater than',KEY_LEN,'!')
		else:
			break
	HASH=key

	rate, arr = fromWav(source)

	time_start=''
	time_end=''
	mes=''
	for i in range(len(arr)):
		e=arr[i]
		f,s=e[0],e[1]
		f=to_bin(f)
		s=to_bin(s)
		lf=f[-1]
		ls=s[-1]
		if len(time_start)<BITS*MARK_LEN:
			print('Collecting Mark: '+str(len(time_start)//BITS)+'/'+str(MARK_LEN),end='\r')
			time_start+=str(lf)
		elif len(time_end)<BITS*MARK_LEN:
			if len(mes)==0:
				print('Collecting Mark: '+str(len(time_start)//BITS)+'/'+str(MARK_LEN))
			mes+=str(lf)
			if ((len(mes)//BITS)-MARK_LEN) >= 0:
				print("Message's Length: "+str(((len(mes)//BITS)-MARK_LEN)),end='\r')
			if lf==time_start[len(time_end)]:
				time_end+=str(lf)
			elif lf==time_start[0]:
				time_end=lf
			else:
				time_end=''
		else:
			print("Message's Length: "+str(((len(mes)//BITS)-MARK_LEN)))
			break
		if len(time_start)<BITS*MARK_LEN:
			print('Collecting Mark: '+str(len(time_start)//BITS)+'/'+str(MARK_LEN),end='\r')
			time_start+=str(ls)
		elif len(time_end)<BITS*MARK_LEN:
			if len(mes)==0:
				print('Collecting Mark: '+str(len(time_start)//BITS)+'/'+str(MARK_LEN))
			mes+=str(ls)
			if ((len(mes)//BITS)-MARK_LEN) >= 0:
				print("Message's Length: "+str(((len(mes)//BITS)-MARK_LEN)),end='\r')
			if ls==time_start[len(time_end)]:
				time_end+=str(ls)
			elif ls==time_start[0]:
				time_end=ls
			else:
				time_end=''
		else:
			print("Message's Length: "+str(((len(mes)//BITS)-MARK_LEN)))
			break

	if time_start==time_end:
		mes=mes[:-len(time_end)]
	else:
		print('ERROR(Key)')
		return -1

	dic=get_dic(time_start+mes)
	if dic==-1:
		print('Wrong Key!')
		return -1

	res=''
	for i in range(len(mes)//BITS):
		byte=mes[:BITS]
		mes=mes[BITS:]
		res+=dic[byte]
	print('Secret Message:',res)


def settings():
	global BITS, KEY_LEN, TIME_SYM, HASH_FUNC
	clear()
	while True:
		print('### SETTINGS ###\n')
		print('All settings will be reset after restart!')
		print('1) Encoding Depth:',BITS)
		print('2) Hash Function:',HASH_FUNC)
		print('0) Back To Menu')
		print()
		ch=str(input('Your Choice: '))
		if ch=='1':
			while True:
				try:
					t=int(input('Encoding Depth: '))
					if t<1:
						print('Encoding depth must be greater!')
					else:
						BITS=t
						clear()
						break
				except:
					print('Input a number!')
		elif ch=='2':
			while True:
				for i in range(len(HASH_FUNCTIONS)):
					print(str(i+1)+') '+HASH_FUNCTIONS[i])
				try:
					t=int(input('Hash Function: '))
					if t<0 or t>len(HASH_FUNCTIONS):
						print('Choice from the list!')
					else:
						HASH_FUNC=HASH_FUNCTIONS[t-1]
						KEY_LEN=len(hashing(HASH_FUNC,'Hello World'))
						clear()
						break
				except Exception as e:
					print(e)
					print('Input a number!')
		elif ch=='0':
			clear()
			return
		else:
			print('No such option!')
			sleep(1)
			clear()


def main():
	while True:
		print('### Audio Encoder ###\n')
		print('1) Encode')
		print('2) Decode')
		print('3) Settings')
		print('0) Exit\n')
		ch=str(input('Your Choice: '))
		if ch=='1':
			while True:
				source=str(input('Source Audio: '))
				if source.find('.wav')==len(source)-4 and source.find('.wav')!=-1:
					pass
				else:
					form = source[len(source)-3:]
					print(form.upper()+' format is not supported!')
					continue
				if '/' not in source and '\\' not in source:
					fs=os.listdir()
					if source in fs:
						break
					else:
						print('No Such File!')
				else:
					if '/' in source and '\\' in source:
						print('Use only one type of slash!')
					else:
						if source.find('/')!=-1:
							di=source[:source.rfind('/')+1]
							f=source[source.rfind('/')+1:]
							try:
								fs=os.listdir(di)
							except:
								print('No Such Directory!')
								continue
							if f in fs:
								break
							else:
								print('No Such File!')
						else:
							di=source[:source.rfind('\\')+1]
							f=source[source.rfind('\\')+1:]
							try:
								fs=os.listdir(di)
							except:
								print('No Such Directory!')
								continue
							if f in fs:
								break
							else:
								print('No Such File!')
			while True:
				result=str(input('Result Audio: '))
				if result.find('.wav')==len(result)-4 and result.find('.wav')!=-1:
					pass
				else:
					form = result[len(result)-3:]
					print(form.upper()+' format is not supported!')
					continue
				if '/' not in result and '\\' not in result:
					fs=os.listdir()
					if result in fs:
						ans=str(input('The file is already exists! Rewrite it?(y/n): '))
						if ans=='y':
							break
						elif ans=='n':
							continue
						else:
							print('Input y or n!')
					else:
						break
				else:
					if '/' in result and '\\' in result:
						print('Use only one type of slash!')
					else:
						if result.find('/')!=-1:
							di=result[:result.rfind('/')+1]
							f=result[result.rfind('/')+1:]
							try:
								fs=os.listdir(di)
							except:
								print('No Such Directory!')
								continue
							if f in fs:
								ans=str(input('The file is already exists! Rewrite it?(y/n): '))
								if ans=='y':
									break
								elif ans=='n':
									continue
								else:
									print('Input y or n!')
							else:
								break
						else:
							di=result[:result.rfind('\\')+1]
							f=result[result.rfind('\\')+1:]
							try:
								fs=os.listdir(di)
							except:
								print('No Such Directory!')
								continue
							if f in fs:
								ans=str(input('The file is already exists! Rewrite it?(y/n): '))
								if ans=='y':
									break
								elif ans=='n':
									continue
								else:
									print('Input y or n!')
							else:
								break
			while True:
				mes=str(input('Message: '))
				if len(mes)==0:
					print('Type Something!')
					continue
				encode(source, result, mes)
				print()				
				break
		elif ch=='2':
			while True:
				source=str(input('Audio: '))
				if source.find('.wav')==len(source)-4 and source.find('.wav')!=-1:
					pass
				else:
					form = source[len(source)-3:]
					print(form.upper()+' format is not supported!')
					continue
				if '/' not in source and '\\' not in source:
					fs=os.listdir()
					if source in fs:
						break
					else:
						print('No Such File!')
				else:
					if '/' in source and '\\' in source:
						print('Use only one type of slash!')
					else:
						if source.find('/')!=-1:
							di=source[:source.rfind('/')+1]
							f=source[source.rfind('/')+1:]
							try:
								fs=os.listdir(di)
							except:
								print('No Such Directory!')
								continue
							if f in fs:
								break
							else:
								print('No Such File!')
						else:
							di=source[:source.rfind('\\')+1]
							f=source[source.rfind('\\')+1:]
							try:
								fs=os.listdir(di)
							except:
								print('No Such Directory!')
								continue
							if f in fs:
								break
							else:
								print('No Such File!')
			while True:
				if decode(source)!=-1:
					print()
					break
		elif ch=='3':
			settings()
		elif ch=='0':
			return -1
		else:
			print('No such option!')
			sleep(1)
			clear()


if __name__=='__main__':
	clear()
	if main()==-1:
		exit()