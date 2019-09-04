extern crate rug;
extern crate rand;

use rug::Integer;
use rug::ops::{Pow, RemRounding};
use rand::{OsRng, Rng};

#[derive(Debug, PartialEq, Clone)]
struct Point {
    x: Integer,
    y: Integer,
}

trait Invert<P, Output> {
    fn invert(self, p:P) -> Output;
}

impl Invert<Integer, Point> for Point {
    fn invert(self, p:Integer) -> Point {
        Point {x: self.x, y: p - self.y }
    }
}

fn point_add(p1: &Point, p2: &Point) -> Point {
    let p = hex2int("fffffffffffffffffffffffffffffffeffffffffffffffff");
    let a = p.clone()-Integer::from(3);

    let id = Point {
        x: Integer::from(0),
        y: Integer::from(1)
    };

    if p1 == &id {
        return Point{x:p2.x.clone(), y:p2.y.clone()}
    }

    if p2 == &id {
        return Point{x:p1.x.clone(), y:p1.y.clone()}
    }

    if p1 == &p2.clone().invert(p.clone()) {
        return id
    }

    let delta = if p1 == p2 {
        (3*p1.x.clone().pow(2)+&a)*Integer::from((2u32*p1.y.clone()).invert_ref(&p).unwrap())
    } else {
        (p2.y.clone()-p1.y.clone()) * Integer::from((p2.x.clone()-p1.x.clone()).invert_ref(&p).unwrap())
    };

    let x = delta.clone().pow(2)-p1.x.clone()-p2.x.clone();
    let y = delta*(p1.x.clone()-x.clone())-p1.y.clone();
    
    Point{
        x: x.rem_floor(&p),
        y: y.rem_floor(&p)
    }
}

fn point_multiply(baseorder: &Integer, p: &Point) -> Point {
    let P = hex2int("fffffffffffffffffffffffffffffffeffffffffffffffff");
    let mut p = p.clone();
    let mut baseorder = baseorder.clone();
    let mut q = Point {
        x: Integer::from(0),
        y: Integer::from(1)
    };
    
    while baseorder > 0 {
        if baseorder.clone()&1 == Integer::from(1) {
            q = point_add(&q,&p);
        }
        p = point_add(&p,&p);
        baseorder = baseorder >> 1;
    }
    
    Point{
        x: q.x.rem_floor(&P),
        y: q.y.rem_floor(&P)
    }

}

fn generate_keypair() -> (Integer, Point) {
    let base = Point{                
        x: hex2int("188da80eb03090f67cbf20eb43a18800f4ff0afd82ff1012"),
        y: hex2int("07192b95ffc8da78631011ed6b24cdd573f977a11e794811"),
    };

    let private = gen_random();
    let public = point_multiply(&private, &base);

    (private, public)
}

fn sign(h: &str, private: Integer) -> (Integer, Integer) {
    let base = Point{               
        x: hex2int("188da80eb03090f67cbf20eb43a18800f4ff0afd82ff1012"),
        y: hex2int("07192b95ffc8da78631011ed6b24cdd573f977a11e794811"),
    };
    let baseorder = hex2int("ffffffffffffffffffffffff99def836146bc9b1b4d22831");

    let z = hex2int(h);
    let k = gen_random();
    let P = point_multiply(&k, &base);
    
    if P.x == Integer::from(0) {
        sign(h, private.clone());
    }

    let r = P.x;
    let s = (z+r.clone()*private)*Integer::from(k.invert_ref(&baseorder).unwrap()).rem_floor(&baseorder);

    (r,s)
}

fn verify_signature(signature: (Integer, Integer), public: Point, h: &str) -> bool {
    let base = Point{               
        x: hex2int("188da80eb03090f67cbf20eb43a18800f4ff0afd82ff1012"),
        y: hex2int("07192b95ffc8da78631011ed6b24cdd573f977a11e794811"),
    };
    let baseorder = hex2int("ffffffffffffffffffffffff99def836146bc9b1b4d22831");

    let r = signature.0;
    let s = signature.1;
    
    if 1 > r && r > baseorder.clone()-Integer::from(1) && 1 > s && s > baseorder.clone()-Integer::from(1) {
        panic!("Invalid signature");
    }
    
    let z = hex2int(h);
    let u1 = z*Integer::from(s.invert_ref(&baseorder).unwrap()).rem_floor(&baseorder);
    let u2 = r.clone()*Integer::from(s.invert_ref(&baseorder).unwrap()).rem_floor(&baseorder);

    let P = point_add(&point_multiply(&u1, &base), &point_multiply(&u2, &public));
    
    if r == P.x {
      return true
    }

    return false
}
fn hex2int(s: &str) -> Integer {
    Integer::from_str_radix(s,16).unwrap()
}

fn gen_random() -> Integer {
    let mut rng = OsRng::new().expect("Error opening random number generator");
    let num:u32 = rng.next_u32();
    Integer::from(num)    
}

fn main() {
    for x in 0..1000 {
        let keypair = generate_keypair();

        let signature = sign("719609852b46b8ea9a5fcd39eb7bc9088fa36399", keypair.0);

        let verified = verify_signature(signature, keypair.1, "719609852b46b8ea9a5fcd39eb7bc9088fa36399");
        
        assert_eq!(verified, true);
    }

}
