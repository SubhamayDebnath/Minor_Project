import User from "../../models/user.model.js";
import Skill from "../../models/skill.model.js";
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
const usersPage =async (req,res) => {
    try {
        const locals = {
            title: "Dashboard - Users",
            description: "Welcome to Dashboard users",
        };
        const users= await User.find().sort({createdAt:-1});
        res.render("admin/users",{locals,layout:adminLayout,user:req.user,users})
    } catch (error) {
        console.log(`Users Page error : ${error}`);
        res.redirect("/error");
    }
}
/*
    Skills page
*/ 
const skillsPage =async (req,res) => {
    try {
        const locals = {
            title: "Dashboard - Skills",
            description: "Welcome to Dashboard skills",
        };
        let perPage = 6;
        let page = req.query.page || 1;
        const skills = await Skill.find()
        .sort({ createdAt: -1 })
        .skip(perPage * page - perPage)
        .limit(perPage)
        .exec();
        const count = await Skill.countDocuments({});
        const totalPages = Math.ceil(count / perPage);
        const nextPage = parseInt(page) + 1;
        const hasNextPage = nextPage <= Math.ceil(count / perPage);
        const prevPage = page > 1 ? page - 1 : null;

        res.render("admin/skills",{
            locals,
            layout:adminLayout
            ,user:req.user,
            skills,
            current: page,
            nextPage: hasNextPage ? nextPage : null,
            prevPage,
            totalPages,
        })
    } catch (error) {
        console.log(`Skills Page error : ${error}`);
        res.redirect("/error");
    }
}
/*
    Skill update form page
*/ 
const skillUpdateForm =async (req,res) => {
    try {
        const locals = {
            title: "Dashboard - Skills update",
            description: "Welcome to Dashboard skills update",
        };
        const skillID=req.params.id;
        const updateSkill=await Skill.findById(skillID);
        res.render("admin/form/update-skill",{locals,layout:adminLayout,user:req.user,updateSkill})
    } catch (error) {
        console.log(`Skills update form page error : ${error}`);
        res.redirect("/error");
    }
}
/*
    Skills page
*/ 
const missingPersonPage =async (req,res) => {
    try {
        const locals = {
            title: "Dashboard - Missing Person",
            description: "Welcome to Dashboard Missing Person",
        };
        res.render("admin/missing-person",{locals,layout:adminLayout,user:req.user})
    } catch (error) {
        console.log(`Missing Person Page error : ${error}`);
        res.redirect("/error");
    }
}
export{
    dashboard,
    usersPage,
    skillsPage,
    missingPersonPage,
    skillUpdateForm
}