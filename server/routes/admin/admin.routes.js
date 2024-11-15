import { Router } from "express";
import { dashboard ,users} from "../../controllers/admin/admin.page.controller.js";
import {isAuthorized} from "../../middlewares/auth.middleware.js"
const router = Router();

router.get("/",isAuthorized,dashboard)
router.get("/users",isAuthorized,users);

export default router;