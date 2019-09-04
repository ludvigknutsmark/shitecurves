from gmpy2 import is_prime
from gmpy2 import invert as I_invert
from Crypto.Random.random import randint

class EC():
    def __init__(self, a, b, base, baseorder, p):
        self.A = a
        self.B = b
        self.base = base
        self.baseorder = baseorder
        self.p = p
        self.id = Point(0,1)

    def __str__(self): 
        return "y^2 = x^3 + "+str(self.A)+"x + "+str(self.B)+" (mod "+str(self.p)+")"

    def add(self,p1, p2):
        if p1 == self.id:
            return p2

        if p2 == self.id:
            return p1
        
        if p1 == p2.invert(self.p):
            return self.id

        if p1 == p2:
            delta = (3*pow(p1.x,2)+self.A)*I_invert(2*p1.y, self.p)
        else:
            delta = (p2.y - p1.y)*I_invert(p2.x - p1.x, self.p)
        
        x = pow(delta, 2)- p1.x - p2.x
        y = delta*(p1.x-x)-p1.y 

        return Point(x % self.p, y % self.p)
    
    def multiply(self,n,p):
        q = self.id
        while n > 0:
            if n&1:
                q = self.add(q,p)
            p = self.add(p,p)
            n = n >> 1
        return q % self.p
    
    def generate_keypair(self): # Diffie-Hellman
        self.private = randint(1, self.baseorder)
        self.public = self.multiply(self.private, self.base)
    
    def sign(self, H):
        z = int("0x"+H, 16)
        k = randint(1,self.baseorder-1)
        P = self.multiply(k,self.base)
        
        if P.x == 0:
            return self.sign(H)
        
        r = P.x
        s = (z+r*self.private)*I_invert(k, self.baseorder)%self.baseorder

        return int(r), int(s)

    def verify_signature(self, signature, pub, H):
        r,s = signature
        if not (1 <= r <= self.baseorder-1 and 1 <= s <= self.baseorder-1):
            raise Exception("Invalid signature")

        z = int("0x"+H, 16)
        u1 = z*I_invert(s,self.baseorder)%self.baseorder
        u2 = r*I_invert(s,self.baseorder)%self.baseorder

        P = self.add(self.multiply(u1,self.base),self.multiply(u2, pub))
        
        if r == P.x:
            return True
        else:
            raise Exception("Invalid signature")

class Point():
    def __init__(self,x,y):
        self.x = x
        self.y = y
    
    def __str__(self):
        return "{"+str(self.x)+", "+str(self.y)+"}"

    def __eq__(self, p2):
        return True if self.x == p2.x and self.y == p2.y else False
    
    def __mod__(self,p):
        return Point(self.x%p, self.y%p)

    def invert(self, p):
        return Point(self.x, p-self.y)
    
if __name__ == "__main__":
    # https://csrc.nist.gov/csrc/media/publications/fips/186/3/archive/2009-06-25/documents/fips_186-3.pdf P-192 parameters
    p = 6277101735386680763835789423207666416083908700390324961279
    n = 6277101735386680763835789423176059013767194773182842284081
    a = p-3
    b = int("0x64210519e59c80e70fa7e9ab72243049feb8deecc146b9b1", 16)
    G = Point(int("0x188da80eb03090f67cbf20eb43a18800f4ff0afd82ff1012",16), int("0x07192b95ffc8da78631011ed6b24cdd573f977a11e794811", 16))

    for i in range(1000):
        ec = EC(a,b,G,n,p)

        ec.generate_keypair()
     
        H = "719609852b46b8ea9a5fcd39eb7bc9088fa36399"    
        r,s = ec.sign(H)
        ec.verify_signature((r,s), ec.public, H)
