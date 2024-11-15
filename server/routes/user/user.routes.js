import { Router } from "express";
import {updateOtherDetails} from "../../controllers/user/user.controllers.js"

const router  = Router();

router.post("/profile/add",updateOtherDetails)

export default router