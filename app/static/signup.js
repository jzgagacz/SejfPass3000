var bcrypt = dcodeIO.bcrypt;

var signupform = document.getElementById("signupform");

var password = document.getElementById("password");
var repeatpassword = document.getElementById("repeatpassword");
var masterpass = document.getElementById("masterpass");
var repeatmasterpass = document.getElementById("repeatmasterpass");

function validPass(pass){
  if (!pass){
    return false;
  }
  if (pass.length < 8){
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

function validateForm() {
    if (password.value !== repeatpassword.value) {
      alert("Podane hasła nie są takie same");
      return false;
    }
    if (masterpass.value !== repeatmasterpass.value) {
      alert("Podane hasła główne nie są takie same");
      return false;
    }
    if (password.value === masterpass.value) {
      alert("Hasło i hasło główne muszą być różne");
      return false;
    }
    if (!validPass(password.value)){
      alert("Za słabe hasło. Hasło musi zawierać co najmniej 8 znaków i zawierać: wielką literę, małą literę, cyfrę oraz znak specjalny.");
      return false;
    }
    if (!validPass(masterpass.value)){
      alert("Za słabe hasło główne. Hasło musi zawierać co najmniej 8 znaków i zawierać: wielką literę, małą literę, cyfrę oraz znak specjalny.");
      return false;
    }
    let hash = bcrypt.hashSync(masterpass.value, 12);
    var masterhashfield = document.createElement('input');
    masterhashfield.setAttribute("name", "masterhash");
    masterhashfield.setAttribute("value", hash);
    masterhashfield.setAttribute("type", "hidden")
    signupform.appendChild(masterhashfield);
}