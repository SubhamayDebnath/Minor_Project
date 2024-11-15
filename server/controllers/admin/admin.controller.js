import Skill from '../../models/skill.model.js'
const addSkill=async (req,res) => {
    try {
        const {name} =req.body;
        if(!name){
            req.flash("error_msg", "Please enter a name");
            return res.redirect("/dashboard/skills");
        }
        const skill = await Skill.find({name:name});
        if(skill){
            req.flash("error_msg", "Skill name is already exist");
            return res.redirect("/dashboard/skills");
        }
        const newSkill=await Skill.create({name});
        if(!newSkill){
            req.flash("error_msg", "Failed to add skill");
            return res.redirect("/dashboard/skills");
        }
        await newSkill.save();
        req.flash("success_msg", "Skill added successfully");
        return res.redirect("/dashboard/skills");

    } catch (error) {
        console.log(`Skill add error : ${error}`);
        res.redirect("/error");
    }
}
export{
    addSkill
}