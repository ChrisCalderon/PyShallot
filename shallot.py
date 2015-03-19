import os
import re
import sys
import gmpy2
import multiprocessing
from hashlib import sha1
from base64 import b64encode, b32encode
from pyasn1.codec.der import encoder
from Queue import Empty as QueueEmpty
from pyasn1.type import univ, namedtype

#### Constants stolen from the original shallot ####
EMIN = 0x10001
EMAX = 0xFFFFFFFFFF

#### Prime finding stuff for RSA ####
def random(bytez):
    '''Produces a random number thats has bytez*8 amount of bits.'''
    return gmpy2.mpz(reduce(lambda a, b: (a << 8)|ord(b), os.urandom(bytez), 0))

def good_prime(p):
    '''True if highly probably prime, else false.'''
    return gmpy2.is_prime(p, 1000) and \
           gmpy2.is_strong_bpsw_prp(p)

def find_prime(bytez=128):
    '''Checks random numbers for primality'''
    p = random(bytez)|1
    while not good_prime(p):
        p = random(bytez)|1
    return p

def good_pair(p, q):
    '''Returns p*q if p and q are a good pair, else 0.'''
    n = p*q
    k = gmpy2.ceil(gmpy2.log2(n))
    if abs(p - q) > 2**(k/2 - 100):
        return n
    return 0

##### Encoding stuffs #####
#https://tools.ietf.org/html/rfc3447#appendix-A.1
class RSAPublicKey(univ.Sequence):
    componentType = namedtype.NamedTypes(
        namedtype.NamedType('modulus', univ.Integer()),
        namedtype.NamedType('publicExponent', univ.Integer())
        )

class RSAPrivateKey(univ.Sequence):
    componentType = namedtype.NamedTypes(
        namedtype.NamedType('version', univ.Integer()),
        namedtype.NamedType('modulus', univ.Integer()),
        namedtype.NamedType('publicExponent', univ.Integer()),
        namedtype.NamedType('privateExponent', univ.Integer()),
        namedtype.NamedType('prime1', univ.Integer()),
        namedtype.NamedType('prime2', univ.Integer()),
        namedtype.NamedType('exponent1', univ.Integer()),
        namedtype.NamedType('exponent2', univ.Integer()),
        namedtype.NamedType('coefficient', univ.Integer())
        )

def public_key(n, e):
    public_key = RSAPublicKey()
    public_key.setComponentByName('modulus', n)
    public_key.setComponentByName('publicExponent', e)
    return encoder.encode(public_key)

def make_onion(n, e):
    return b32encode(sha1(public_key(n, e)).digest())[:16].lower()+'.onion'

def private_key(n, e, d, p, q):
    private_key = RSAPrivateKey()
    private_key.setComponentByName('version', 0)
    private_key.setComponentByName('modulus', n)
    private_key.setComponentByName('publicExponent', e)
    private_key.setComponentByName('privateExponent', d)
    private_key.setComponentByName('prime1', p)
    private_key.setComponentByName('prime2', q)
    private_key.setComponentByName('exponent1', d % (p - 1))
    private_key.setComponentByName('exponent2', d % (q - 1))
    private_key.setComponentByName('coefficient', gmpy2.invert(q, p))
    return encoder.encode(private_key)

def pprint_privkey(privkey):
    print '-'*5 + 'BEGIN RSA PRIVATE KEY' + '-'*5
    encoded = b64encode(privkey)
    while encoded:
        chunk, encoded = encoded[:64], encoded[64:]
        print chunk
    print '-'*5 + 'END RSA PRIVATE KEY' + '-'*5

#### Worker process generates keys, hashes, and checks for patterns ####
class Worker(multiprocessing.Process):

    def __init__(self, regex, results, trials, kill, *args, **kwds):
        multiprocessing.Process.__init__(self, *args, **kwds)
        self.regex = regex
        self.results = results
        self.trials = trials
        self.kill = kill

    def run(self):
        pattern = re.compile(self.regex)
        search = pattern.search
        i = 0
        while True:
            p = find_prime()
            q = find_prime()
            if q > p:
                p, q = q, p
            n = good_pair(p, q)
            if not n:
                continue
            tot = n - (p + q - 1)
            e = EMIN
            while e < EMAX:
                if self.kill.is_set():
                    self.trials.put(i)
                    return
                i += 1
                onion = make_onion(n, e)
                if search(onion) and gmpy2.gcd(e, tot)==1:
                    d = gmpy2.invert(e, tot)
                    priv = private_key(n, e, d, p, q)
                    self.results.put(onion+priv)
                    self.trials.put(i)
                    self.kill.set()
                    return
                e += 2

def kill_procs(processes, results, trials, kill):
    '''joins all processes, empties all queues, and returns sum of trials.'''
    if not kill.is_set():
        kill.set()
    sum_trials = 0
    while not trials.empty():
        sum_trials += trials.get()
    for proc in processes:
        proc.join()
    while not results.empty():
        results.get()
    return sum_trials

#### Main thread ####
def main(pattern):
    results = multiprocessing.Queue()
    trials = multiprocessing.Queue()
    kill = multiprocessing.Event()
    processes = []
    for i in range(multiprocessing.cpu_count()):
        processes.append(Worker(pattern, results, trials, kill))
        processes[-1].start()
    try:
        while True:
            try:
                found = results.get(True, 0.1)
            except QueueEmpty:
                pass
            else:
                break
    except KeyboardInterrupt:
        sum_trials = kill_procs(processes, results, trials, kill)
        print 'Tried', sum_trials, 'public keys before exit'
        sys.exit(1)
    sum_trials = kill_procs(processes, results, trials, kill)
    onion = found[:22]
    privkey = found[22:]
    print '-'*64
    print 'Found matching pattern after', sum_trials, 'tries:', onion
    print '-'*64
    pprint_privkey(privkey)

if __name__ == '__main__':
    try:
        main(sys.argv[1])
    except KeyboardInterrupt:
        sys.exit(1)

