const adminLayout = "../views/layouts/admin";
/*
    Dashboard page
*/ 
const dashboard=async (req,res) => {
    try {
        const locals = {
            title: "Dashboard",
            description: "Welcome to Dashboard",
        };
        res.render("admin/index",{locals,layout:adminLayout,user:req.user})
    } catch (error) {
        console.log(`Dashboard Page error : ${error}`);
        res.redirect("/error");
    }
}
/*
    Users page
*/ 
const users =async (req,res) => {
    try {
        const locals = {
            title: "Dashboard - Users",
            description: "Welcome to Dashboard users",
        };
        res.render("admin/users",{locals,layout:adminLayout,user:req.user})
    } catch (error) {
        console.log(`Users Page error : ${error}`);
        res.redirect("/error");
    }
}
export{
    dashboard,
    users
}