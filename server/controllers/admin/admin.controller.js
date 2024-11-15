const addSkill=async (req,res) => {
    try {
        console.log(req.body);
    } catch (error) {
        console.log(`Skill add error : ${error}`);
        res.redirect("/error");
    }
}
export{
    addSkill
}