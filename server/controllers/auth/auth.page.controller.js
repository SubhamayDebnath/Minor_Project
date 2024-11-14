const authenticationLayout = "../views/layouts/authentication";
/*
  Register Page 
*/
const registerPage = async (req, res) => {
    try {
      res.render("auth/register",{layout:authenticationLayout});
    } catch (error) {
      console.log(`Register Page Error: ${error}`);
      res.redirect("/error");
    }
};
/*
  Login Page 
*/
const loginPage = async (req, res) => {
  try {
    res.render("auth/login",{layout:authenticationLayout});
  } catch (error) {
    console.log(`Login Page Error: ${error}`);
    res.redirect("/error");
  }
};
  
export { registerPage,loginPage };