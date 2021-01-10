var bcrypt = dcodeIO.bcrypt;

var passform = document.getElementById("passform");

var name = document.getElementById("name");
var password = document.getElementById("password");
var masterpass = document.getElementById("masterpass");

var decryptbtn = document.getElementsByClassName("decryptbtn")

function validPass(pass){
  if (!pass){
    return false;
  }
  if (pass.length < 8 || pass.length > 40){
    return false;
  }
  if (!/\d/.test(pass)){
    return false;
  }
  if (!/[a-z]/.test(pass)){
    return false;
  }
  if (!/[A-Z]/.test(pass)){
    return false;
  }
  if (!/\W/.test(pass)){
    return false;
  }
  return true;
}

Array.prototype.slice.call(decryptbtn).forEach(element => {
  element.addEventListener("click", function(ev){
    if (ev.target.parentNode.getElementsByClassName("masterfield")[0] === undefined){
      let masterfield = document.createElement("input")
      masterfield.type = "password";
      masterfield.placeholder = "Hasło główne";
      masterfield.className = "masterfield";
      ev.target.parentNode.insertBefore(masterfield, ev.target)
      return
    }
    var arrpass = JSON.parse(ev.target.parentNode.getElementsByClassName("arrpass")[0].textContent)
    var arrsalt = JSON.parse(ev.target.parentNode.getElementsByClassName("salt")[0].textContent)
    var arriv = JSON.parse(ev.target.parentNode.getElementsByClassName("iv")[0].textContent)
    var barrpass = new Uint8Array(arrpass)
    var salt = new Uint8Array(arrsalt)
    var iv = new Uint8Array(arriv)
    var masterpw = ev.target.parentNode.getElementsByClassName("masterfield")[0].value
    getmasterhash(async function(result){
      let masterhash = result;
      if (masterhash == undefined || masterhash == "None"){
          alert("Nie można sprawdzić hasła głównego")
          return false;
      }
      if (!bcrypt.compareSync(masterpw, masterhash)){
          alert("Niepoprawne hasło główne")
          return false;
      }
      let keyMaterial = await getKeyMaterial(masterpw);
      let key = await getKey(keyMaterial, salt);
      try {
        let decrypted = await window.crypto.subtle.decrypt(
          {
            name: "AES-GCM",
            iv: iv
          },
          key,
          barrpass
        );
  
        let dec = new TextDecoder()
        ev.target.parentNode.getElementsByClassName("encpass")[0].textContent = "hasło: " + dec.decode(decrypted)
        ev.target.parentNode.getElementsByClassName("masterfield")[0].remove()
        ev.target.parentNode.getElementsByClassName("decryptbtn")[0].remove()
      } catch (e) {
        alert("Bład podczas odszyfrowywania")
      }
    })
  });
})

function getKeyMaterial(pass) {
  let password = pass;
  let enc = new TextEncoder();
  return window.crypto.subtle.importKey(
    "raw",
    enc.encode(password),
    "PBKDF2",
    false,
    ["deriveBits", "deriveKey"]
  );
}

function getKey(keyMaterial, salt) {
  return window.crypto.subtle.deriveKey(
    {
      "name": "PBKDF2",
      salt: salt, 
      "iterations": 100000,
      "hash": "SHA-256"
    },
    keyMaterial,
    { "name": "AES-GCM", "length": 256},
    true,
    [ "encrypt", "decrypt" ]
  );
}

async function encrypt(plaintext, salt, iv, pass) {
  let keyMaterial = await getKeyMaterial(pass);
  let key = await getKey(keyMaterial, salt);
  let ec = new TextEncoder();
  return window.crypto.subtle.encrypt(
    {
      name: "AES-GCM",
      iv: iv
    },
    key,
    ec.encode(plaintext)
  );
}

function getmasterhash(callback) {
  var result = undefined;
  var xhr = new XMLHttpRequest();
  xhr.open("GET", "/masterhash");
  xhr.onreadystatechange = function() {
      var DONE = 4;
      var OK = 200;
      if (xhr.readyState == DONE) {
          if (xhr.status == OK) {
              result = xhr.responseText;
          } else {
              alert("Nie można sprawdzić hasła głównego")
          }
          callback(result)
      }
  }
  xhr.send(null);
}

async function validatePassForm() {
  if (!validPass(password.value)){
    alert("Za słabe hasło. Hasło musi zawierać od 8 do 40 znaków i zawierać: wielką literę, małą literę, cyfrę oraz znak specjalny.");
    return false;
  }
  getmasterhash(async function(result) {      
    let masterhash = result;
    if (masterhash == undefined || masterhash == "None"){
      alert("Nie można sprawdzić hasła głównego")
      return false;
    }
    if (!bcrypt.compareSync(masterpass.value, masterhash)){
      alert("Niepoprawne hasło główne")
      return false;
    }
    let salt = window.crypto.getRandomValues(new Uint8Array(16));
    let iv = window.crypto.getRandomValues(new Uint8Array(12));
    let encr = await encrypt(password.value, salt, iv, masterpass.value);
    let encryptedpw = buffer = new Uint8Array(encr)
    var encryptedpwfield = document.createElement('input');
    encryptedpwfield.setAttribute("name", "encryptedpw");
    encryptedpwfield.setAttribute("value", encryptedpw);
    encryptedpwfield.setAttribute("type", "hidden")
    passform.appendChild(encryptedpwfield);

    var saltfield = document.createElement('input');
    saltfield.setAttribute("name", "salt");
    saltfield.setAttribute("value", salt);
    saltfield.setAttribute("type", "hidden")
    passform.appendChild(saltfield);

    var ivfield = document.createElement('input');
    ivfield.setAttribute("name", "iv");
    ivfield.setAttribute("value", iv);
    ivfield.setAttribute("type", "hidden")
    passform.appendChild(ivfield);
    passform.submit()
  })
}
