import { Router } from "express";
import { dashboard } from "../../controllers/admin/admin.page.controller.js";
import {isAuthorized} from "../../middlewares/auth.middleware.js"
const router = Router();

router.get("/",isAuthorized,dashboard)

export default router;