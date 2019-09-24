#[derive(PartialEq, Eq, Debug)]
pub struct Profile {
    pub email: String,
    pub uid: usize,
    pub role: String,
}

impl Profile {
    pub fn new(email: String) -> Profile {
        if email.contains('&') || email.contains('=') {
            panic!("Invalid email");
        }

        Profile {
            email,
            uid: 0,
            role: "user".into()
        }
    }

    pub fn from_string(s: &str) -> Profile {
        let mut email = None;
        let mut uid = None;
        let mut role = None;

        for part in s.split('&') {
            let mut subparts = part.split('=');
            let key = subparts.next().unwrap();
            let value = subparts.next().unwrap();

            match key {
                "email" => email = Some(value.to_owned()),
                "uid" => uid = Some(value.parse().unwrap()),
                "role" => role = Some(value.to_owned()),
                _ => panic!("Unknown key"),
            }
        }

        assert!(email.is_some());
        assert!(uid.is_some());
        assert!(role.is_some());

        Profile {
            email: email.unwrap(),
            uid: uid.unwrap(),
            role: role.unwrap(),
        }
    }

    pub fn encode_as_string(&self) -> String {
        format!("email={}&uid={}&role={}", self.email, self.uid, self.role)
    }
}

#[test]
fn test_profile_as_string() {
    let p = Profile::new("test@example.com".into());
    let s = p.encode_as_string();
    assert_eq!(s, "email=test@example.com&uid=0&role=user");
}

#[test]
fn test_profile_roundtrip() {
    let p1 = Profile::new("test@example.com".into());
    let s = p1.encode_as_string();
    let p2 = Profile::from_string(&s);
    assert_eq!(p1, p2);
}
