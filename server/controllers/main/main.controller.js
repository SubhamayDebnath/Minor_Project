import Skill from '../../models/skill.model.js'
/*
  Home Page 
*/
const homePage = async (req, res) => {
  try {
    const locals = {
      title: "Disaster Management",
      description: "Disaster Management",
    };
    res.render("index",{locals,user:req.user});
  } catch (error) {
    console.log(`Home Page Error: ${error}`);
    res.redirect("/error");
  }
};
/*
  Missing Person Page 
*/
const missingPersonPage = async (req, res) => {
  try {
    const locals = {
      title: "Disaster Management",
      description: "Disaster Management",
    };
    res.render("missing-person",{locals,user:req.user});
  } catch (error) {
    console.log(`Missing Person Page Error: ${error}`);
    res.redirect("/error");
  }
};
/*
  Profile Page 
*/
const profilePage=async(req,res)=>{
  try {
    const locals = {
      title: "Profile - Disaster Management",
      description: "Disaster Management",
    };
    if(req.user){
      const skills = await Skill.find();
      res.render("profile",{locals,user:req.user,skills});
    }else{
  
      req.flash("error_msg", "Please log in to continue this page.");
      return res.redirect("/login");
    }

  } catch (error) {
    console.log(`Profile Page Error: ${error}`);
    res.redirect("/error");
  }
}

/*
  Error Page 
*/
const utilsLayout = "../views/layouts/utils";
const errorPage = async (req, res) => {
  res.render("error/error", {
    locals: { title: "Error", description: "Error page" },
    layout: utilsLayout,
  });
};
export { homePage, errorPage,missingPersonPage ,profilePage};
