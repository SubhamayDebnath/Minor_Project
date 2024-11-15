// bloodGroup: 'A+',
//   allergies: 'dsad',
//   ' medicalProblems': 'sadsad',
//   skills: '673738dfda3029df13c978fd',
//   isAvailable: 'true',
//   isRescuer: 'true'

import { config } from "dotenv";
import fs from "fs/promises";
config();
import User from "../../models/user.model.js";
import cloudinary from "../../utils/cloudinary.js";
import sendEmail from "../../utils/sendMail.js";

const updateOtherDetails=async (req,res) => {
    try {
        const {bloodGroup,allergies,medicalProblems,skills,isAvailable,isRescuer}=req.body;
        if(!allergies || medicalProblems){
            req.flash("error_msg", "Please fill in all fields");
            return res.redirect("/profile");
        }
        let image = "";
        let public_id = "";
        if (!req.file) {
            req.flash("error_msg", "Please upload an image.");
            return res.redirect("/profile");
        }
        if (req.file) {
            const transformationOptions = {
              transformation: [
                {
                  quality: "auto:low",
                  fetch_format: "avif",
                },
              ],
            };
      
            const cloudinaryResult = await cloudinary.uploader.upload(
              req.file.path,
              transformationOptions
            );
            image = cloudinaryResult.secure_url;
            public_id = cloudinaryResult.public_id;
            fs.rm(req.file.path);
          }
        const user = await User.findByIdAndUpdate(req.user._id, {
            bloodGroup:bloodGroup,
            allergies:allergies.split(","),
            medicalProblems:medicalProblems.split(","),
            skills:skills,
            isAvailable:isAvailable===true,
            isRescuer:isRescuer===true
        })
        if(!user){

        }
    } catch (error) {
        console.log(`Other details page error : ${error}`);
        res.redirect("/error");
    }
}
export{
    updateOtherDetails
}