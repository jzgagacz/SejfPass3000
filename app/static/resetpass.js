var password = document.getElementById("password");
var repeatpassword = document.getElementById("repeatpassword");

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

function validateForm() {
    if (password.value !== repeatpassword.value) {
      alert("Podane hasła nie są takie same");
      return false;
    }
    if (!validPass(password.value)){
      alert("Za słabe hasło. Hasło musi zawierać od 8 do 40 znaków i zawierać: wielką literę, małą literę, cyfrę oraz znak specjalny.");
      return false;
    }
}