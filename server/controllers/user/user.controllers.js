const updateOtherDetails=async (req,res) => {
    try {
        console.log(req.body);
    } catch (error) {
        console.log(`Other details page error : ${error}`);
        res.redirect("/error");
    }
}
export{
    updateOtherDetails
}