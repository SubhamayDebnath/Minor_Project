const adminLayout = "../views/layouts/admin";
const dashboard=async (req,res) => {
    try {
        const locals = {
            title: "Dashboard",
            description: "Welcome to Dashboard",
        };
        res.render("admin/index",{locals,layout:adminLayout,user:req.user})
    } catch (error) {
        console.log(`Dashboard error : ${error}`);
        res.redirect("/error");
    }
}
export{
    dashboard
}