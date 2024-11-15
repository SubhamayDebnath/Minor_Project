import { Router } from "express";
import upload from '../../middlewares/multer.middleware.js'
import {isAuthenticated} from '../../middlewares/auth.middleware.js'
import {updateOtherDetails} from "../../controllers/user/user.controllers.js"

const router  = Router();

router.post("/profile/add",isAuthenticated,upload.single("avatar"),updateOtherDetails)

export default router