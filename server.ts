import express from "express";
import type { Request, Response, NextFunction } from "express";
import { createServer as createViteServer } from "vite";
import path from "path";
import { fileURLToPath } from "url";
import { Server } from "socket.io";
import { createServer } from "http";
import dotenv from "dotenv";
import jwt from "jsonwebtoken";
import bcrypt from "bcryptjs";
import Anthropic from '@anthropic-ai/sdk';
import nodemailer from 'nodemailer';
import multer from 'multer';
import { GoogleGenAI, Type } from '@google/genai';
import { query } from "./server/db.ts";
import { initDb } from "./server/init-db.ts";
import warehouseRoutes from "./server/routes/warehouse.ts";

dotenv.config();

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

const JWT_SECRET = process.env.JWT_SECRET;
if (!JWT_SECRET && process.env.NODE_ENV === 'production') {
  console.warn("WARNING: JWT_SECRET environment variable is not set in production. Using a default fallback secret. This is insecure for production use.");
}
const SAFE_JWT_SECRET = JWT_SECRET || "pharmaflow-dev-secret-key-2026";

import { z } from "zod";
import rateLimit from "express-rate-limit";

const loginLimiter = rateLimit({
  windowMs: 15 * 60 * 1000, // 15 minutes
  max: 100, // Limit each IP to 100 login requests per windowMs
  message: { error: "Too many login attempts, please try again after 15 minutes" },
  standardHeaders: true,
  legacyHeaders: false,
});

async function startServer() {
  // Initialize Database
  await initDb();

  const app = express();
  app.set('trust proxy', 1);
  const httpServer = createServer(app);
  const io = new Server(httpServer, {
    cors: { origin: process.env.NODE_ENV === 'production' ? process.env.APP_URL : "*" }
  });

  app.use(express.json({ limit: '50mb' }));

  // --- Middleware ---

  // Multi-Tenant Middleware
  const tenantMiddleware = async (req: Request & { companyId?: number }, res: Response, next: NextFunction) => {
    // In a real SaaS, we'd use subdomain or a custom header
    // For this demo, we'll assume the company_id is passed in headers or extracted from JWT
    const companyId = req.headers['x-company-id'];
    if (companyId) {
      req.companyId = parseInt(companyId as string);
    }
    next();
  };

  // Auth Middleware
  const authMiddleware = (req: Request & { user?: any, companyId?: number }, res: Response, next: NextFunction) => {
    const token = req.headers.authorization?.split(' ')[1];
    if (!token) return res.status(401).json({ error: "Unauthorized" });

    try {
      const decoded = jwt.verify(token, SAFE_JWT_SECRET) as any;
      req.user = decoded;
      req.companyId = decoded.companyId;
      next();
    } catch (err) {
      return res.status(401).json({ error: "Invalid token" });
    }
  };

  app.use(tenantMiddleware);

  // --- Socket.io ---
  io.on("connection", (socket) => {
    socket.on("join-room", (room) => socket.join(room));
    socket.on("weighing-update", (data) => {
      io.to(`weighing-${data.batchId}`).emit("live-weighing", data);
    });
  });

  // --- Anthropic AI ---
  const ANTHROPIC_API_KEY = process.env.ANTHROPIC_API_KEY;
  const anthropic = new Anthropic({ apiKey: ANTHROPIC_API_KEY || "DUMMY_KEY" });

  // --- Error Reporting Pipeline ---
  app.post("/api/errors/analyze", async (req, res) => {
    const { error, stack, context, source } = req.body;
    console.error(`[ERROR_ANALYZE][${source}]`, error);

    try {
      // 1. Claude Analysis
      let claudeAnalysis = "Claude analysis skipped (no API key).";
      if (ANTHROPIC_API_KEY && ANTHROPIC_API_KEY !== "DUMMY_KEY") {
        try {
          const claudeResponse = await anthropic.messages.create({
            model: "claude-3-5-sonnet-20240620",
            max_tokens: 1024,
            messages: [{
              role: "user",
              content: `Analyze this website error and suggest a fix.
              Error: ${error}
              Stack: ${stack}
              Context: ${JSON.stringify(context)}
              Source: ${source}`
            }],
          });
          // @ts-ignore
          claudeAnalysis = claudeResponse.content[0].text;
        } catch (claudeErr: any) {
          console.error("Claude Analysis Failure:", claudeErr);
          claudeAnalysis = `Claude analysis failed: ${claudeErr.message || "Unknown error"}`;
        }
      }

      res.json({ claudeAnalysis });
    } catch (err) {
      console.error("Claude Analysis Failure:", err);
      res.status(500).json({ error: "Failed to analyze error" });
    }
  });

  app.post("/api/errors/notify", async (req, res) => {
    const { error, claudeAnalysis, geminiSteps } = req.body;

    // Log the report
    console.log("\n--- AI ERROR REPORT ---");
    console.log("ERROR:", error);
    console.log("CLAUDE ANALYSIS:", claudeAnalysis);
    console.log("\nGEMINI STEPS:", geminiSteps);
    console.log("------------------------\n");

    // Optional: Send Email
    if (process.env.SMTP_HOST && process.env.SMTP_USER && process.env.SMTP_PASS) {
      try {
        const transporter = nodemailer.createTransport({
          host: process.env.SMTP_HOST,
          port: Number(process.env.SMTP_PORT || 587),
          secure: process.env.SMTP_SECURE === 'true',
          auth: {
            user: process.env.SMTP_USER,
            pass: process.env.SMTP_PASS,
          },
        });

        await transporter.sendMail({
          from: '"PharmaFlow Error Bot" <errors@pharmaflow.com>',
          to: process.env.ADMIN_EMAIL || "admin@example.com",
          subject: `🚨 Error Detected: ${String(error).substring(0, 50)}`,
          text: `Error: ${error}\n\nClaude Analysis:\n${claudeAnalysis}\n\nGemini Implementation Steps:\n${geminiSteps}`,
        });
        console.log("Error report email sent.");
      } catch (emailErr) {
        console.error("Failed to send error email:", emailErr);
      }
    }

    res.json({ success: true });
  });

  const safeJsonParse = (str: string, fallback: any = {}) => {
    try {
      return JSON.parse(str || '{}');
    } catch (e) {
      return fallback;
    }
  };

  // --- Audit Logger ---
  const logAudit = async (companyId: number, userId: number, action: string, type: string, id: number | null, details: string, oldVal?: any, newVal?: any, reason?: string) => {
    try {
      const tz = Intl.DateTimeFormat().resolvedOptions().timeZone;
      await query(`
        INSERT INTO audit_logs (company_id, user_id, action, target_type, target_id, details, old_value, new_value, reason, timezone) 
        VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10)
        RETURNING id
      `, [
        companyId, 
        userId, 
        action, 
        type, 
        id ?? null, 
        details ?? null, 
        oldVal ?? null, 
        newVal ?? null, 
        reason ?? null, 
        tz
      ]);
    } catch (err) {
      console.error("Audit Log Error:", err);
    }
  };

  // --- API Routes ---
  app.use("/api/warehouse", authMiddleware, warehouseRoutes);

  // Auth
  const loginSchema = z.object({
    username: z.string().min(3).max(50),
    password: z.string().min(8),
    companySubdomain: z.string().optional().default('demo')
  });

  app.post("/api/auth/login", loginLimiter, async (req, res) => {
    try {
      const { username, password, companySubdomain } = loginSchema.parse(req.body);
      
      // Find company
      const companyRes = await query("SELECT id FROM companies WHERE subdomain = $1", [companySubdomain]);
      if (companyRes.rows.length === 0) return res.status(404).json({ error: "Company not found" });
      const companyId = companyRes.rows[0].id;

      // Find user
      const userRes = await query("SELECT * FROM users WHERE company_id = $1 AND username = $2", [companyId, username]);
      if (userRes.rows.length === 0) return res.status(401).json({ error: "Invalid credentials" });
      
      const user = userRes.rows[0];
      if (!user.is_active) return res.status(403).json({ error: "Account deactivated" });

      const isMatch = await bcrypt.compare(password, user.password_hash);
      if (!isMatch) {
        return res.status(401).json({ error: "Invalid credentials" });
      }

      const token = jwt.sign({ id: user.id, companyId: user.company_id, role: user.role }, SAFE_JWT_SECRET, { expiresIn: '8h' });
      
      await logAudit(companyId, user.id, "LOGIN", "user", user.id, `User logged in: ${username}`);
      
      let permissions = safeJsonParse(user.permissions);
      
      return res.json({ 
        token, 
        user: { 
          id: user.id, 
          username: user.username, 
          role: user.role, 
          full_name: user.full_name, 
          company_id: user.company_id,
          permissions
        } 
      });
    } catch (err) {
      console.error("Login Error:", err);
      return res.status(500).json({ error: "Server error" });
    }
  });

  // Workflows
  app.get("/api/workflows", authMiddleware, async (req: any, res) => {
    try {
      const { status } = req.query;
      let sql = "SELECT * FROM workflows WHERE company_id = $1";
      const params: any[] = [req.companyId];

      if (status) {
        sql += " AND status = $2";
        params.push(status);
      }

      sql += " ORDER BY created_at DESC";
      const result = await query(sql, params);
      res.json(result.rows || []);
    } catch (err) {
      res.status(500).json({ error: "Failed to fetch workflows" });
    }
  });

  app.get("/api/workflows/:id", authMiddleware, async (req: Request & { companyId?: number }, res: Response) => {
    const { id } = req.params;
    try {
      const workflowRes = await query("SELECT * FROM workflows WHERE id = $1 AND company_id = $2", [id, req.companyId]);
      if (workflowRes.rows.length === 0) return res.status(404).json({ error: "Workflow not found" });
      
      const stepsRes = await query("SELECT * FROM workflow_steps WHERE workflow_id = $1 ORDER BY step_order ASC", [id]);
      const workflow = workflowRes.rows[0];
      workflow.steps = stepsRes.rows.map(s => {
        const config = safeJsonParse(s.config) || {};
        const aiMetadata = config._ai_metadata || {};
        delete config._ai_metadata;
        return { 
          ...s, 
          config,
          confidence: aiMetadata.confidence,
          source_reference: aiMetadata.source_reference
        };
      });
      
      return res.json(workflow);
    } catch (err) {
      return res.status(500).json({ error: "Failed to fetch workflow" });
    }
  });

  const workflowSchema = z.object({
    id: z.number().optional(),
    name: z.string().min(1),
    description: z.string().optional(),
    status: z.enum(['Draft', 'Released', 'Effective', 'Deleted']).optional().default('Draft'),
    steps: z.array(z.object({
      name: z.string().min(1),
      type: z.string(),
      responsible_role: z.string().optional(),
      confidence: z.string().optional(),
      source_reference: z.string().optional(),
      config: z.any().optional()
    }))
  });

  const upload = multer({ storage: multer.memoryStorage() });

  app.post("/api/workflows/generate", authMiddleware, upload.single('file'), async (req: Request & { user?: any, companyId?: number }, res: Response) => {
    try {
      if (!req.file) {
        return res.status(400).json({ error: "No file uploaded" });
      }

      const apiKey = process.env.GEMINI_API_KEY || process.env.API_KEY;
      if (!apiKey) {
        console.error("Gemini API key is missing (GEMINI_API_KEY or API_KEY)");
        return res.status(500).json({ error: "Gemini API key is not configured. Please set GEMINI_API_KEY in environment variables." });
      }
      const ai = new GoogleGenAI({ apiKey });
      
      const response = await ai.models.generateContent({
        model: "gemini-3-flash-preview",
        contents: [
          {
            inlineData: {
              data: req.file.buffer.toString('base64'),
              mimeType: req.file.mimetype
            }
          },
          "Convert this document into a structured workflow. Extract the title, description, and a sequence of steps. For each step, identify the name (MANDATORY, do not leave empty), type (e.g., 'text', 'number', 'date', 'dropdown', 'file', 'comment', 'calculation', 'table', 'multi-field'), the responsible role (e.g., 'Operator', 'Reviewer', 'QA Approver'), and any specific configuration like required fields or labels. Also provide a confidence score (High, Medium, Low) and a source reference (e.g., 'Page 1, Section 2') for each step. If a step requires multiple inputs, use the 'multi-field' type and define the sub-fields in the config. Ensure every step has a non-empty name."
        ],
        config: {
          responseMimeType: "application/json",
          responseSchema: {
            type: Type.OBJECT,
            properties: {
              name: { type: Type.STRING },
              description: { type: Type.STRING },
              confidence_overall: { type: Type.STRING, description: "High, Medium, or Low" },
              steps: {
                type: Type.ARRAY,
                items: {
                  type: Type.OBJECT,
                  properties: {
                    id: { type: Type.STRING, description: "A unique string ID for the step" },
                    name: { type: Type.STRING },
                    type: { type: Type.STRING, description: "Must be one of: text, number, date, dropdown, file, comment, calculation, table, multi-field" },
                    responsible_role: { type: Type.STRING },
                    confidence: { type: Type.STRING, description: "High, Medium, or Low" },
                    source_reference: { type: Type.STRING },
                    is_inferred: { type: Type.BOOLEAN },
                    config: {
                      type: Type.OBJECT,
                      properties: {
                        label: { type: Type.STRING },
                        required: { type: Type.BOOLEAN },
                        fields: {
                          type: Type.ARRAY,
                          items: {
                            type: Type.OBJECT,
                            properties: {
                              id: { type: Type.STRING },
                              name: { type: Type.STRING },
                              type: { type: Type.STRING },
                              config: {
                                type: Type.OBJECT,
                                properties: {
                                  label: { type: Type.STRING },
                                  required: { type: Type.BOOLEAN }
                                }
                              }
                            }
                          }
                        }
                      }
                    }
                  },
                  required: ["id", "name", "type", "responsible_role"]
                }
              }
            },
            required: ["name", "description", "steps"]
          }
        }
      });

      let generatedWorkflow;
      try {
        const text = response.text || '{}';
        // Clean up potential markdown code blocks if Gemini returns them despite the mimeType
        const cleanText = text.replace(/```json\n?|```/g, '').trim();
        generatedWorkflow = JSON.parse(cleanText);
        
        // Ensure all steps have names to avoid validation errors
        if (generatedWorkflow.steps && Array.isArray(generatedWorkflow.steps)) {
          generatedWorkflow.steps = generatedWorkflow.steps.map((step: any, idx: number) => ({
            ...step,
            name: step.name || `Step ${idx + 1}`
          }));
        }
      } catch (parseErr) {
        console.error("AI Response Parsing Error:", parseErr, "Raw Text:", response.text);
        return res.status(500).json({ error: "AI returned invalid data format" });
      }
      
      // Log the AI generation event
      if (req.user && req.companyId) {
        await logAudit(
          req.companyId, 
          req.user.id, 
          "AI_WORKFLOW_GENERATED", 
          "workflow", 
          0, // 0 because it's not saved to DB yet
          `AI generated workflow from document: ${req.file.originalname}`
        );
      }

      return res.json(generatedWorkflow);
    } catch (err: any) {
      console.error("AI Workflow Generation Error:", err);
      if (err.message?.includes("API key not valid") || err.status === "INVALID_ARGUMENT") {
        return res.status(401).json({ error: "Invalid Gemini API key. Please check your configuration." });
      }
      return res.status(500).json({ error: "Failed to generate workflow from document" });
    }
  });

  app.post("/api/workflows", authMiddleware, async (req: Request & { user?: any, companyId?: number }, res: Response) => {
    try {
      const { id, name, description, steps, status } = workflowSchema.parse(req.body);
      
      let workflowId = id;
      if (id) {
        await query("UPDATE workflows SET name = $1, description = $2, status = $3 WHERE id = $4 AND company_id = $5", [name, description, status, id, req.companyId]);
        await query("DELETE FROM workflow_steps WHERE workflow_id = $1", [id]);
      } else {
        const result = await query(`
          INSERT INTO workflows (company_id, name, description, status)
          VALUES ($1, $2, $3, $4)
          RETURNING id
        `, [req.companyId, name, description, status]);
        
        if (result.rows.length === 0) throw new Error("Failed to insert workflow");
        workflowId = result.rows[0].id;
      }

      for (let i = 0; i < steps.length; i++) {
        const step = steps[i];
        await query(`
          INSERT INTO workflow_steps (workflow_id, name, type, step_order, responsible_role, config)
          VALUES ($1, $2, $3, $4, $5, $6)
          RETURNING id
        `, [
          workflowId, 
          step.name, 
          step.type, 
          i + 1, 
          step.responsible_role, 
          JSON.stringify({
            ...step.config,
            _ai_metadata: {
              confidence: step.confidence,
              source_reference: step.source_reference
            }
          })
        ]);
      }

      await logAudit(req.companyId, req.user.id, id ? "WORKFLOW_UPDATED" : "WORKFLOW_CREATED", "workflow", workflowId, `Workflow ${name} saved`);
      return res.json({ id: workflowId });
    } catch (err) {
      if (err instanceof z.ZodError) {
        console.error("Workflow Validation Error:", JSON.stringify(err.issues, null, 2));
        return res.status(400).json({ error: "Invalid workflow data", details: err.issues });
      }
      console.error("Workflow Save Error:", err);
      return res.status(500).json({ error: "Failed to save workflow" });
    }
  });

  // Instances (Batch Records)
  app.get("/api/instances", authMiddleware, async (req: any, res) => {
    const page = parseInt(req.query.page as string) || 1;
    const limit = parseInt(req.query.limit as string) || 50;
    const status = req.query.status as string;
    const offset = (page - 1) * limit;

    let sql = `
      SELECT i.*, w.name as workflow_name, u.full_name as creator_name
      FROM batch_records i
      JOIN workflows w ON i.workflow_id = w.id
      JOIN users u ON i.created_by = u.id
      WHERE i.company_id = $1
    `;
    const params: any[] = [req.companyId];

    if (status) {
      sql += ` AND i.status = $${params.length + 1}`;
      params.push(status);
    }

    sql += ` ORDER BY i.created_at DESC LIMIT $${params.length + 1} OFFSET $${params.length + 2}`;
    params.push(limit, offset);

    const result = await query(sql, params);

    let countSql = "SELECT count(*) as count FROM batch_records WHERE company_id = $1";
    const countParams: any[] = [req.companyId];
    if (status) {
      countSql += " AND status = $2";
      countParams.push(status);
    }
    const countRes = await query(countSql, countParams);
    const total = countRes.rows[0].count;

    // For the supply chain scheduling tab, it expects the array directly if it's not paginated or if it's a specific request
    if (status === 'Scheduled') {
      return res.json(result.rows);
    }

    res.json({ data: result.rows, total, page, limit });
  });

  app.get("/api/instances/:id", authMiddleware, async (req: any, res) => {
    const { id } = req.params;
    const instanceRes = await query(`
      SELECT i.*, w.name as workflow_name, u.full_name as creator_name
      FROM batch_records i
      JOIN workflows w ON i.workflow_id = w.id
      JOIN users u ON i.created_by = u.id
      WHERE i.id = $1 AND i.company_id = $2
    `, [id, req.companyId]);
    
    if (instanceRes.rows.length === 0) return res.status(404).json({ error: "Instance not found" });
    
    const instance = instanceRes.rows[0];
    const stepsRes = await query("SELECT * FROM workflow_steps WHERE workflow_id = $1 ORDER BY step_order ASC", [instance.workflow_id]);
    instance.steps = stepsRes.rows.map(s => ({ ...s, config: safeJsonParse(s.config, {}) }));
    
    const dataRes = await query("SELECT d.*, u.full_name as submitted_by_name FROM batch_data d JOIN users u ON d.submitted_by = u.id WHERE d.batch_id = $1 ORDER BY d.version DESC", [id]);
    instance.data = dataRes.rows.map(d => ({ ...d, data: safeJsonParse(d.data, {}) }));
    
    res.json(instance);
  });

  const instanceSchema = z.object({
    workflowId: z.number(),
    batchNumber: z.string().min(1),
    productName: z.string().min(1),
    scheduledAt: z.string().nullable().optional(),
    status: z.string().optional().default('Work in Process')
  });

  app.post("/api/instances", authMiddleware, async (req: Request & { user?: any, companyId?: number }, res: Response) => {
    try {
      const { workflowId, batchNumber, productName, scheduledAt, status } = instanceSchema.parse(req.body);
      
      const result = await query(`
        INSERT INTO batch_records (company_id, workflow_id, batch_number, product_name, created_by, scheduled_at, status)
        VALUES ($1, $2, $3, $4, $5, $6, $7)
        RETURNING id
      `, [req.companyId, workflowId, batchNumber, productName, req.user.id, scheduledAt, status || 'Work in Process']);
      
      if (result.rows.length === 0) throw new Error("Failed to insert batch record");
      const id = result.rows[0].id;
      
      await logAudit(req.companyId, req.user.id, "BATCH_CREATED", "batch_record", id, `Batch ${batchNumber} created/scheduled`);
      return res.json({ id });
    } catch (err) {
      console.error("Batch Creation Error:", err);
      return res.status(500).json({ error: "Failed to create batch" });
    }
  });

  app.post("/api/instances/:id/submit", authMiddleware, async (req: any, res) => {
    const { id } = req.params;
    const { stepId, data, isNa, naReason, reason } = req.body;
    try {
      // Get current version for this step
      const currentRes = await query(`
        SELECT version, data FROM batch_data 
        WHERE batch_id = $1 AND step_id = $2 
        ORDER BY version DESC LIMIT 1
      `, [id, stepId]);
      
      const currentVersion = currentRes.rows.length > 0 ? currentRes.rows[0].version : 0;
      const oldData = currentRes.rows.length > 0 ? currentRes.rows[0].data : null;
      const nextVersion = currentVersion + 1;

      await query(`
        INSERT INTO batch_data (batch_id, step_id, data, is_na, na_reason, submitted_by, version)
        VALUES ($1, $2, $3, $4, $5, $6, $7)
        RETURNING id
      `, [id, stepId, JSON.stringify(data || {}), isNa ? 1 : 0, naReason, req.user.id, nextVersion]);
      
      // Update updated_at
      await query("UPDATE batch_records SET updated_at = CURRENT_TIMESTAMP WHERE id = $1", [id]);

      // Audit Log
      await logAudit(
        req.companyId, 
        req.user.id, 
        currentVersion === 0 ? "CREATE" : "UPDATE", 
        "batch_step", 
        stepId, 
        `Step ${stepId} submitted (v${nextVersion})`,
        oldData,
        JSON.stringify(data || {}),
        reason || (currentVersion === 0 ? "Initial submission" : "Revision")
      );
      
      return res.json({ success: true, version: nextVersion });
    } catch (err) {
      console.error("Step Submission Error:", err);
      return res.status(500).json({ error: "Failed to submit step data" });
    }
  });

  app.post("/api/instances/:id/review", authMiddleware, async (req: any, res) => {
    const { id } = req.params;
    const { action, comment, finalStatus } = req.body;
    try {
      const status = finalStatus || (action === 'Approve' ? 'Completed' : 'Under Review');
      await query("UPDATE batch_records SET status = $1, updated_at = CURRENT_TIMESTAMP WHERE id = $2", [status, id]);

      await logAudit(
        req.companyId,
        req.user.id,
        "REVIEW",
        "batch_record",
        parseInt(id),
        `Batch ${action}ed. Final Status: ${status}`,
        null,
        JSON.stringify({ action, comment, status }),
        comment || "Batch review completed"
      );

      res.json({ success: true, status });
    } catch (err) {
      console.error("Review Error:", err);
      res.status(500).json({ error: "Failed to process review" });
    }
  });

  app.get("/api/instances/:id/audit-report", authMiddleware, async (req: any, res) => {
    const { id } = req.params;
    try {
      const auditTrail = await query(`
        SELECT a.*, u.full_name as user_name
        FROM audit_logs a
        JOIN users u ON a.user_id = u.id
        WHERE a.target_type = 'batch_step' AND a.target_id IN (
          SELECT id FROM workflow_steps WHERE workflow_id = (
            SELECT workflow_id FROM batch_records WHERE id = $1
          )
        )
        ORDER BY a.created_at DESC
      `, [id]);

      res.json(auditTrail.rows);
    } catch (err) {
      res.status(500).json({ error: "Failed to fetch audit report" });
    }
  });

  // E-Signature Verification
  app.post("/api/auth/verify-signature", authMiddleware, async (req: Request & { user?: any, companyId?: number }, res: Response) => {
    const { password, meaning, batchId, stepId } = req.body;
    const userId = req.user.id;

    try {
      const userRes = await query("SELECT password_hash FROM users WHERE id = $1", [userId]);
      if (userRes.rows.length === 0) return res.status(404).json({ error: "User not found" });
      
      const isMatch = await bcrypt.compare(password, userRes.rows[0].password_hash);
      if (!isMatch) return res.status(401).json({ error: "Invalid password for signature" });

      // Record signature
      const result = await query(`
        INSERT INTO signatures (batch_id, step_id, user_id, meaning, timezone)
        VALUES ($1, $2, $3, $4, $5)
        RETURNING *
      `, [batchId || null, stepId || null, userId, meaning, Intl.DateTimeFormat().resolvedOptions().timeZone]);

      if (result.rows.length === 0) throw new Error("Failed to record signature");
      const signature = result.rows[0];

      await logAudit(req.companyId, userId, "SIGNATURE", "batch_record", batchId || null, `Signed as ${meaning} for step ${stepId || 'N/A'}`);

      return res.json({ success: true, signature });
    } catch (err) {
      console.error("Signature Error:", err);
      return res.status(500).json({ error: "Signature failed" });
    }
  });

  // Master Data: Products
  app.get("/api/products", authMiddleware, async (req: any, res) => {
    const result = await query("SELECT * FROM products WHERE company_id = $1", [req.companyId]);
    res.json(result.rows);
  });

  app.post("/api/products", authMiddleware, async (req: any, res) => {
    const { name, code, strength, dosageForm, batchSize, instructionsRef } = req.body;
    try {
      const result = await query(`
        INSERT INTO products (company_id, name, code, strength, dosage_form, batch_size_standard, instructions_ref)
        VALUES ($1, $2, $3, $4, $5, $6, $7)
        RETURNING *
      `, [req.companyId, name, code, strength, dosageForm, batchSize, instructionsRef]);
      
      return res.json(result.rows[0]);
    } catch (err) {
      console.error("Product Creation Error:", err);
      return res.status(500).json({ error: "Failed to create product" });
    }
  });

  // Master Data: Materials
  app.get("/api/materials", authMiddleware, async (req: any, res) => {
    const result = await query("SELECT * FROM materials WHERE company_id = $1", [req.companyId]);
    res.json(result.rows);
  });

  app.post("/api/materials", authMiddleware, async (req: any, res) => {
    const { name, code, supplier, specifications, storageConditions } = req.body;
    try {
      const result = await query(`
        INSERT INTO materials (company_id, name, code, supplier, specifications, storage_conditions)
        VALUES ($1, $2, $3, $4, $5, $6)
        RETURNING *
      `, [req.companyId, name, code, supplier, specifications, storageConditions]);
      
      return res.json(result.rows[0]);
    } catch (err) {
      console.error("Material Creation Error:", err);
      return res.status(500).json({ error: "Failed to create material" });
    }
  });

  // Deviations
  app.post("/api/deviations", authMiddleware, async (req: any, res) => {
    const { batchId, stepId, description } = req.body;
    try {
      const result = await query(`
        INSERT INTO deviations (company_id, batch_id, step_id, description)
        VALUES ($1, $2, $3, $4)
        RETURNING *
      `, [req.companyId, batchId, stepId, description]);
      
      const deviation = result.rows[0];
      await logAudit(req.companyId, req.user.id, "DEVIATION_CREATED", "deviation", deviation.id, `Deviation created for batch ${batchId}`);
      
      return res.json(deviation);
    } catch (err) {
      console.error("Deviation Creation Error:", err);
      return res.status(500).json({ error: "Failed to create deviation" });
    }
  });

  // Admin: Users
  app.get("/api/admin/users", authMiddleware, async (req: any, res) => {
    if (req.user.role !== 'Admin') return res.status(403).json({ error: "Forbidden" });
    const result = await query("SELECT id, username, full_name, role, is_active, last_login_at FROM users WHERE company_id = $1", [req.companyId]);
    res.json(result.rows);
  });

  app.post("/api/admin/users/:id/status", authMiddleware, async (req: any, res) => {
    if (req.user.role !== 'Admin') return res.status(403).json({ error: "Forbidden" });
    const { id } = req.params;
    const { isActive } = req.body;
    await query("UPDATE users SET is_active = $1 WHERE id = $2 AND company_id = $3", [isActive ? 1 : 0, id, req.companyId]);
    res.json({ success: true });
  });

  app.put("/api/admin/users/:id", authMiddleware, async (req: any, res) => {
    if (req.user.role !== 'Admin') return res.status(403).json({ error: "Forbidden" });
    const { id } = req.params;
    const { role, full_name, permissions } = req.body;
    await query(`
      UPDATE users 
      SET role = $1, full_name = $2, permissions = $3 
      WHERE id = $4 AND company_id = $5
    `, [role, full_name, JSON.stringify(permissions), id, req.companyId]);
    res.json({ success: true });
  });

  // Stats
  app.get("/api/stats", authMiddleware, async (req: any, res) => {
    const totalWorkflows = (await query("SELECT count(*) as count FROM workflows WHERE company_id = $1", [req.companyId])).rows[0].count;
    const activeInstances = (await query("SELECT count(*) as count FROM batch_records WHERE company_id = $1 AND status = 'Executing'", [req.companyId])).rows[0].count;
    const pendingReviews = (await query("SELECT count(*) as count FROM batch_records WHERE company_id = $1 AND status = 'Under Review'", [req.companyId])).rows[0].count;
    const completedInstances = (await query("SELECT count(*) as count FROM batch_records WHERE company_id = $1 AND status = 'Completed'", [req.companyId])).rows[0].count;
    
    res.json({ totalWorkflows, activeInstances, pendingReviews, completedInstances });
  });

  // Dashboard Layouts
  app.get("/api/dashboard/layout", authMiddleware, async (req: any, res) => {
    try {
      // 1. Check for user-specific layout
      const userLayout = await query(`
        SELECT layout_json, widgets_json 
        FROM user_dashboards 
        WHERE user_id = $1 AND company_id = $2 AND is_active = 1
      `, [req.user.id, req.companyId]);

      if (userLayout.rows.length > 0) {
        return res.json({
          layout: JSON.parse(userLayout.rows[0].layout_json),
          widgets: JSON.parse(userLayout.rows[0].widgets_json),
          source: 'user'
        });
      }

      // 2. Check for role-based layout
      const roleLayout = await query(`
        SELECT layout_json, widgets_json 
        FROM role_dashboards 
        WHERE role = $1 AND company_id = $2
      `, [req.user.role, req.companyId]);

      if (roleLayout.rows.length > 0) {
        return res.json({
          layout: JSON.parse(roleLayout.rows[0].layout_json),
          widgets: JSON.parse(roleLayout.rows[0].widgets_json),
          source: 'role'
        });
      }

      // 3. Fallback to a standard default layout
      res.json({
        layout: [
          { i: 'stats', x: 0, y: 0, w: 12, h: 2, static: true },
          { i: 'batches_chart', x: 0, y: 2, w: 6, h: 4 },
          { i: 'inventory_alerts', x: 6, y: 2, w: 6, h: 4 }
        ],
        widgets: [
          { id: 'stats', type: 'kpi_group', title: 'Global Metrics', source: 'global' },
          { id: 'batches_chart', type: 'chart', title: 'Batch Status Distribution', source: 'batches', visualization: 'pie' },
          { id: 'inventory_alerts', type: 'list', title: 'Critical Inventory Alerts', source: 'inventory', visualization: 'list' }
        ],
        source: 'default'
      });
    } catch (err) {
      res.status(500).json({ error: "Failed to fetch dashboard layout" });
    }
  });

  app.post("/api/dashboard/layout", authMiddleware, async (req: any, res) => {
    try {
      const { layout, widgets } = req.body;
      
      // Upsert user dashboard
      const existing = await query("SELECT id FROM user_dashboards WHERE user_id = $1 AND company_id = $2", [req.user.id, req.companyId]);
      
      if (existing.rows.length > 0) {
        await query(`
          UPDATE user_dashboards 
          SET layout_json = $1, widgets_json = $2, updated_at = CURRENT_TIMESTAMP 
          WHERE id = $3
        `, [JSON.stringify(layout), JSON.stringify(widgets), existing.rows[0].id]);
      } else {
        await query(`
          INSERT INTO user_dashboards (user_id, company_id, layout_json, widgets_json) 
          VALUES ($1, $2, $3, $4)
        `, [req.user.id, req.companyId, JSON.stringify(layout), JSON.stringify(widgets)]);
      }

      // Audit log
      await query(`
        INSERT INTO audit_logs (company_id, user_id, action, target_type, details) 
        VALUES ($1, $2, 'UPDATE_DASHBOARD_LAYOUT', 'Dashboard', 'User updated their custom dashboard layout')
      `, [req.companyId, req.user.id]);

      res.json({ success: true });
    } catch (err) {
      res.status(500).json({ error: "Failed to save dashboard layout" });
    }
  });

  // Widget Data Endpoint
  app.get("/api/dashboard/widgets/data", authMiddleware, async (req: any, res) => {
    const { source, type, filters } = req.query as any;
    try {
      let data: any = [];
      const parsedFilters = filters ? JSON.parse(filters) : {};

      switch (source) {
        case 'global':
          const totalWorkflows = (await query("SELECT count(*) as count FROM workflows WHERE company_id = $1", [req.companyId])).rows[0].count;
          const activeInstances = (await query("SELECT count(*) as count FROM batch_records WHERE company_id = $1 AND status = 'Executing'", [req.companyId])).rows[0].count;
          const pendingReviews = (await query("SELECT count(*) as count FROM batch_records WHERE company_id = $1 AND status = 'Under Review'", [req.companyId])).rows[0].count;
          const completedInstances = (await query("SELECT count(*) as count FROM batch_records WHERE company_id = $1 AND status = 'Completed'", [req.companyId])).rows[0].count;
          
          if (type === 'kpi_group') {
            data = [
              { label: 'Total Workflows', value: totalWorkflows },
              { label: 'Active Batches', value: activeInstances },
              { label: 'Pending Reviews', value: pendingReviews },
              { label: 'Completed', value: completedInstances }
            ];
          } else if (type === 'chart') {
            data = [
              { name: 'Workflows', value: parseInt(totalWorkflows) },
              { name: 'Active', value: parseInt(activeInstances) },
              { name: 'Pending', value: parseInt(pendingReviews) },
              { name: 'Completed', value: parseInt(completedInstances) }
            ];
          } else if (type === 'list') {
            data = [
              { title: 'Active Batches', subtitle: 'Currently executing', value: activeInstances, status: 'Success' },
              { title: 'Pending Reviews', subtitle: 'Awaiting QA', value: pendingReviews, status: 'Warning' }
            ];
          } else {
            data = { totalWorkflows, activeInstances, pendingReviews, completedInstances };
          }
          break;
        case 'batches':
          if (type === 'kpi_group' || type === 'kpi') {
            const total = (await query("SELECT count(*) as count FROM batch_records WHERE company_id = $1", [req.companyId])).rows[0].count;
            const active = (await query("SELECT count(*) as count FROM batch_records WHERE company_id = $1 AND status = 'Executing'", [req.companyId])).rows[0].count;
            const completed = (await query("SELECT count(*) as count FROM batch_records WHERE company_id = $1 AND status = 'Completed'", [req.companyId])).rows[0].count;
            
            data = [
              { label: 'Total Batches', value: total },
              { label: 'Active', value: active },
              { label: 'Completed', value: completed }
            ];
          } else if (type === 'chart') {
             const res = await query(`
                SELECT status as name, count(*)::int as value 
                FROM batch_records 
                WHERE company_id = $1 
                GROUP BY status
              `, [req.companyId]);
              data = res.rows;
          } else if (type === 'list') {
            const res = await query(`
              SELECT batch_number as title, product_name as subtitle, status as value 
              FROM batch_records 
              WHERE company_id = $1 
              ORDER BY updated_at DESC 
              LIMIT 5
            `, [req.companyId]);
            data = res.rows.map(r => ({
              ...r,
              status: r.value === 'Executing' ? 'Success' : r.value === 'Under Review' ? 'Warning' : 'Neutral'
            }));
          } else {
            const res = await query("SELECT * FROM batch_records WHERE company_id = $1 ORDER BY created_at DESC LIMIT 10", [req.companyId]);
            data = res.rows;
          }
          break;
        case 'inventory':
          if (type === 'kpi_group' || type === 'kpi') {
            const totalItems = (await query("SELECT count(*) as count FROM inventory WHERE company_id = $1", [req.companyId])).rows[0].count;
            const lowStock = (await query("SELECT count(*) as count FROM materials WHERE company_id = $1 AND quantity <= (tolerance_range * 100)", [req.companyId])).rows[0].count;
            data = [
              { label: 'Total Items', value: totalItems },
              { label: 'Low Stock', value: lowStock, trend: -5 }
            ];
          } else if (type === 'list') {
            const res = await query(`
              SELECT name as title, sku as subtitle, quantity || ' ' || unit as value, 
              CASE WHEN quantity <= (tolerance_range * 100) THEN 'Critical' ELSE 'Success' END as status
              FROM materials 
              WHERE company_id = $1 
              ORDER BY quantity ASC
              LIMIT 10
            `, [req.companyId]);
            data = res.rows;
          } else if (type === 'chart') {
            const res = await query(`
              SELECT name, quantity::float as value 
              FROM materials 
              WHERE company_id = $1 
              LIMIT 5
            `, [req.companyId]);
            data = res.rows;
          } else {
            const res = await query(`
              SELECT i.*, m.name as material_name 
              FROM inventory i 
              JOIN materials m ON i.material_id = m.id 
              WHERE i.company_id = $1 
              LIMIT 10
            `, [req.companyId]);
            data = res.rows;
          }
          break;
        case 'production':
          if (type === 'kpi_group') {
            const res = await query(`
              SELECT status as label, count(*)::int as value 
              FROM batch_records 
              WHERE company_id = $1 
              GROUP BY status
            `, [req.companyId]);
            data = res.rows;
          } else {
            const prodRes = await query(`
              SELECT status as name, count(*)::int as value 
              FROM batch_records 
              WHERE company_id = $1 
              GROUP BY status
            `, [req.companyId]);
            data = prodRes.rows;
          }
          break;
        case 'quality':
          if (type === 'kpi_group') {
            const totalDeviations = (await query("SELECT count(*) as count FROM deviations WHERE company_id = $1", [req.companyId])).rows[0].count;
            const openDeviations = (await query("SELECT count(*) as count FROM deviations WHERE company_id = $1 AND status = 'Open'", [req.companyId])).rows[0].count;
            data = [
              { label: 'Total Deviations', value: totalDeviations },
              { label: 'Open', value: openDeviations, trend: openDeviations > 0 ? 10 : 0 }
            ];
          } else if (type === 'list') {
            const res = await query(`
              SELECT id as title, description as subtitle, status as value,
              CASE WHEN status = 'Open' THEN 'Critical' ELSE 'Success' END as status
              FROM deviations 
              WHERE company_id = $1 
              ORDER BY created_at DESC 
              LIMIT 5
            `, [req.companyId]);
            data = res.rows;
          } else {
            data = [];
          }
          break;
        default:
          data = [];
      }
      res.json(data);
    } catch (err) {
      res.status(500).json({ error: "Failed to fetch widget data" });
    }
  });

  // Audit Logs
  app.get("/api/audit", authMiddleware, async (req: any, res) => {
    const page = parseInt(req.query.page as string) || 1;
    const limit = parseInt(req.query.limit as string) || 50;
    const offset = (page - 1) * limit;

    const result = await query(`
      SELECT a.*, u.full_name as user_name, u.role as user_role 
      FROM audit_logs a 
      JOIN users u ON a.user_id = u.id 
      WHERE a.company_id = $1 
      ORDER BY a.created_at DESC 
      LIMIT $2 OFFSET $3
    `, [req.companyId, limit, offset]);

    const countRes = await query("SELECT count(*) as count FROM audit_logs WHERE company_id = $1", [req.companyId]);
    const total = countRes.rows[0].count;

    res.json({ data: result.rows, total, page, limit });
  });

  // Dashboard Charts
  app.get("/api/dashboard/charts", authMiddleware, async (req: any, res) => {
    try {
      const statusRes = await query(`
        SELECT status as name, count(*) as value 
        FROM batch_records 
        WHERE company_id = $1 
        GROUP BY status
      `, [req.companyId]);

      const trendRes = await query(`
        SELECT date(created_at) as date, count(*) as count 
        FROM batch_records 
        WHERE company_id = $1 AND created_at >= date('now', '-7 days')
        GROUP BY date(created_at)
        ORDER BY date ASC
      `, [req.companyId]);

      res.json({
        statusDist: statusRes.rows,
        yieldTrend: trendRes.rows
      });
    } catch (err) {
      res.status(500).json({ error: "Failed to fetch dashboard charts" });
    }
  });

  // MRP Alerts
  app.get("/api/mrp/alerts", authMiddleware, async (req: any, res) => {
    try {
      const lowStock = await query(`
        SELECT id, name, sku, quantity, unit, tolerance_range as reorder_point 
        FROM materials 
        WHERE company_id = $1 AND quantity <= (tolerance_range * 100) -- Using tolerance_range as a proxy for reorder point for now
      `, [req.companyId]);

      const expiringSoon = await query(`
        SELECT id, name, sku, quantity, unit, expiry_date 
        FROM materials 
        WHERE company_id = $1 AND expiry_date <= date('now', '+30 days')
      `, [req.companyId]);

      res.json({
        lowStock: lowStock.rows,
        expiringSoon: expiringSoon.rows
      });
    } catch (err) {
      res.status(500).json({ error: "Failed to fetch MRP alerts" });
    }
  });

  // Inventory
  app.get("/api/inventory", authMiddleware, async (req: any, res) => {
    try {
      const inventory = await query(`
        SELECT i.*, 
               m.name as name, 
               m.name as material_name,
               m.code as code,
               m.sku as sku,
               m.type as material_type, 
               m.potency as potency,
               m.tolerance_range as tolerance_range,
               m.unit as unit,
               b.name as location_name,
               100 as reorder_point
        FROM inventory i
        JOIN materials m ON i.material_id = m.id
        LEFT JOIN bins b ON i.location_id = b.id
        WHERE i.company_id = $1
      `, [req.companyId]);
      const equipment = await query("SELECT * FROM equipment WHERE company_id = $1", [req.companyId]);
      res.json({
        materials: inventory.rows, // Sending inventory records as 'materials' for frontend compatibility
        equipment: equipment.rows
      });
    } catch (err) {
      res.status(500).json({ error: "Failed to fetch inventory" });
    }
  });

  app.get("/api/equipment", authMiddleware, async (req: any, res) => {
    const result = await query("SELECT * FROM equipment WHERE company_id = $1", [req.companyId]);
    res.json(result.rows);
  });

  app.get("/api/warehouses", authMiddleware, async (req: any, res) => {
    res.json({
      warehouses: [
        { id: 1, name: 'Main Warehouse', location: 'Building A' },
        { id: 2, name: 'Cold Storage', location: 'Building B' }
      ],
      bins: [
        { id: 1, warehouse_id: 1, name: 'A-01', zone: 'Ambient', is_allergen_zone: false },
        { id: 2, warehouse_id: 2, name: 'C-01', zone: 'Cold', is_allergen_zone: true }
      ]
    });
  });

  app.get("/api/boms", authMiddleware, async (req: any, res) => {
    res.json([
      { id: 1, product_name: 'Paracetamol 500mg', version: '1.0', created_at: new Date().toISOString(), status: 'Approved' },
      { id: 2, product_name: 'Amoxicillin 250mg', version: '2.1', created_at: new Date().toISOString(), status: 'Under Review' }
    ]);
  });

  app.get("/api/purchase-orders", authMiddleware, async (req: any, res) => {
    res.json([
      { id: 1, po_number: 'PO-2026-001', vendor_name: 'Global Chemicals', total_amount: 15000, status: 'Open' },
      { id: 2, po_number: 'PO-2026-002', vendor_name: 'Pharma Supplies Inc', total_amount: 8500, status: 'Closed' }
    ]);
  });

  app.get("/api/shipments", authMiddleware, async (req: any, res) => {
    res.json([
      { id: 1, shipment_number: 'SHP-9988', customer_name: 'City Hospital', carrier: 'FedEx', status: 'Shipped' },
      { id: 2, shipment_number: 'SHP-9989', customer_name: 'MediCare Pharmacy', carrier: 'DHL', status: 'Pending' }
    ]);
  });

  app.get("/api/inspections", authMiddleware, async (req: any, res) => {
    res.json([
      { id: 1, target_type: 'Material', inspector_name: 'John Doe', created_at: new Date().toISOString(), results: 'All parameters within spec', status: 'Passed' },
      { id: 2, target_type: 'Batch', inspector_name: 'Jane Smith', created_at: new Date().toISOString(), results: 'Minor deviation in color', status: 'Failed' }
    ]);
  });

  app.get("/api/maintenance", authMiddleware, async (req: any, res) => {
    res.json([
      { id: 1, equipment_name: 'Tablet Press A', type: 'Preventive', performed_by: 'Tech Team', description: 'Lubrication and belt check', created_at: new Date().toISOString() },
      { id: 2, equipment_name: 'Blender B', type: 'Repair', performed_by: 'External Service', description: 'Motor replacement', created_at: new Date().toISOString() }
    ]);
  });

  // Financials
  app.get("/api/financials", authMiddleware, async (req: any, res) => {
    res.json({
      summary: {
        total_spent: 850000,
        total_revenue: 1250000,
        total_waste: 45000
      },
      transactions: [
        { id: 1, type: 'Sale', description: 'Batch #BN-123456 Sale', amount: 25000, timestamp: new Date().toISOString() },
        { id: 2, type: 'Waste', description: 'Batch #BN-654321 Material Loss', amount: 1200, timestamp: new Date().toISOString() }
      ]
    });
  });

  // Search
  app.get("/api/search", authMiddleware, async (req: any, res) => {
    const { q } = req.query;
    const queryStr = `%${q}%`;
    try {
      const workflows = await query("SELECT 'Workflow' as type, name as label, 'workflows' as tab, id FROM workflows WHERE company_id = $1 AND name LIKE $2", [req.companyId, queryStr]);
      const batches = await query("SELECT 'Batch' as type, batch_number as label, 'instances' as tab, id FROM batch_records WHERE company_id = $1 AND batch_number LIKE $2", [req.companyId, queryStr]);
      const materials = await query("SELECT 'Material' as type, name as label, 'inventory' as tab, id FROM materials WHERE company_id = $1 AND (name LIKE $2 OR code LIKE $2)", [req.companyId, queryStr]);
      const equipment = await query("SELECT 'Equipment' as type, name as label, 'inventory' as tab, id FROM equipment WHERE company_id = $1 AND (name LIKE $2 OR asset_id LIKE $2)", [req.companyId, queryStr]);
      
      res.json([...workflows.rows, ...batches.rows, ...materials.rows, ...equipment.rows]);
    } catch (err) {
      res.status(500).json({ error: "Search failed" });
    }
  });

  // AI Insights
  app.get("/api/ai/insights", authMiddleware, async (req: any, res) => {
    try {
      // Dynamic insights based on data
      const lowStockCount = (await query("SELECT count(*) as count FROM materials WHERE company_id = $1 AND quantity <= (tolerance_range * 100)", [req.companyId])).rows[0].count;
      const pendingReviews = (await query("SELECT count(*) as count FROM batch_records WHERE company_id = $1 AND status = 'Under Review'", [req.companyId])).rows[0].count;
      const deviations = (await query("SELECT count(*) as count FROM deviations WHERE company_id = $1 AND status = 'Open'", [req.companyId])).rows[0].count;

      const insights = [];
      if (lowStockCount > 0) {
        insights.push({
          id: 101,
          type: 'inventory',
          title: 'Stock Replenishment Required',
          description: `${lowStockCount} materials are below reorder points. Potential production delay for upcoming batches.`,
          severity: 'high',
          iconType: 'Package',
          recommendation: 'Initiate purchase orders for low-stock raw materials immediately.'
        });
      }
      if (pendingReviews > 0) {
        insights.push({
          id: 102,
          type: 'compliance',
          title: 'Batch Release Bottleneck',
          description: `${pendingReviews} batch records are awaiting review. Average release time is increasing.`,
          severity: 'medium',
          iconType: 'Clock',
          recommendation: 'Assign additional reviewers to clear the backlog of pending batch records.'
        });
      }
      if (deviations > 0) {
        insights.push({
          id: 103,
          type: 'quality',
          title: 'Open Deviations Alert',
          description: `There are ${deviations} open deviations requiring investigation.`,
          severity: 'high',
          iconType: 'AlertTriangle',
          recommendation: 'Prioritize root cause analysis for open deviations to prevent recurrence.'
        });
      }

      // Add some static AI-like insights if list is short
      if (insights.length < 2) {
        insights.push({
          id: 1,
          type: 'maintenance',
          title: 'Predictive Maintenance Alert',
          description: 'Mixer-04 showing abnormal vibration patterns. Failure predicted within 48-72 hours of operation.',
          severity: 'high',
          iconType: 'Activity',
          recommendation: 'Schedule inspection and lubrication before next batch.'
        });
      }

      res.json(insights);
    } catch (err) {
      res.status(500).json({ error: "Failed to fetch AI insights" });
    }
  });

  // Inventory Extensions
  app.get("/api/inventory/genealogy", authMiddleware, async (req: any, res) => {
    try {
      const batches = await query(`
        SELECT i.id, i.batch_number, i.product_name, i.created_at, i.status
        FROM batch_records i
        WHERE i.company_id = $1
        ORDER BY i.created_at DESC
        LIMIT 5
      `, [req.companyId]);

      const genealogy = batches.rows.map(batch => ({
        id: `batch-${batch.id}`,
        type: 'Batch',
        label: batch.batch_number,
        details: `${batch.product_name} - ${batch.status}`,
        timestamp: batch.created_at,
        children: [
          {
            id: `dispensing-${batch.id}`,
            type: 'Dispensing',
            label: `DISP-${batch.batch_number}`,
            details: 'Material Dispensing Completed',
            timestamp: batch.created_at,
            children: [
              {
                id: `lot-${batch.id}`,
                type: 'Lot',
                label: `LOT-${batch.batch_number.split('-')[1] || '9921'}`,
                details: 'Raw Material Lot Used',
                timestamp: batch.created_at
              }
            ]
          }
        ]
      }));

      res.json(genealogy);
    } catch (err) {
      res.status(500).json({ error: "Failed to fetch genealogy" });
    }
  });

  app.post("/api/inventory/equipment/verify-cleaning", authMiddleware, async (req: any, res) => {
    const { equipmentId, agent, swabResult, signature } = req.body;
    await query("UPDATE equipment SET status = 'Cleaned' WHERE id = $1 AND company_id = $2", [equipmentId, req.companyId]);
    await logAudit(req.companyId, req.user.id, "CLEANING_VERIFIED", "equipment", equipmentId, `Equipment ${equipmentId} cleaning verified with agent ${agent}. Result: ${swabResult}`);
    res.json({ success: true });
  });

  app.post("/api/inventory/equipment/status", authMiddleware, async (req: any, res) => {
    const { id, status } = req.body;
    await query("UPDATE equipment SET status = $1 WHERE id = $2 AND company_id = $3", [status, id, req.companyId]);
    await logAudit(req.companyId, req.user.id, "STATUS_CHANGE", "equipment", id, `Equipment status changed to ${status}`);
    res.json({ success: true });
  });

  app.post("/api/inventory/move", authMiddleware, async (req: any, res) => {
    const { materialId, fromBin, toBin, quantity } = req.body;
    // Mock move logic
    await logAudit(req.companyId, req.user.id, "MATERIAL_MOVE", "material", materialId, `Moved ${quantity} from bin ${fromBin} to ${toBin}`);
    res.json({ success: true });
  });

  app.get("/api/reports/financials", authMiddleware, async (req: any, res) => {
    // In a real app, this would calculate costs from labor, materials, and overhead
    res.json([
      { name: 'Batch A-101', cost: 4500, profit: 1200, labor: 800 },
      { name: 'Batch A-102', cost: 4200, profit: 1500, labor: 750 },
      { name: 'Batch B-205', cost: 5100, profit: 900, labor: 950 },
      { name: 'Batch C-098', cost: 3800, profit: 1800, labor: 600 },
      { name: 'Batch D-112', cost: 4700, profit: 1100, labor: 850 },
    ]);
  });
  app.post("/api/weighing/complete", authMiddleware, async (req: Request & { user?: any, companyId?: number }, res: Response) => {
    const { materialId, equipmentId, batchId, tareWeight, grossWeight, netWeight, unit, signature, comments } = req.body;
    try {
      const result = await query(`
        INSERT INTO weighing_transactions (company_id, material_id, equipment_id, batch_id, tare_weight, gross_weight, net_weight, unit, operator_id, signature, comments)
        VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11)
        RETURNING id
      `, [req.companyId, materialId, equipmentId, batchId, tareWeight, grossWeight, netWeight, unit, req.user.id, signature, comments]);
      
      if (result.rows.length === 0) throw new Error("Failed to insert weighing transaction");
      const transactionId = result.rows[0].id;

      await logAudit(req.companyId, req.user.id, "WEIGHING_COMPLETED", "weighing_transaction", transactionId, `Weighed ${netWeight}${unit} for batch ${batchId}`);
      
      // Update material quantity
      await query("UPDATE materials SET quantity = quantity - $1 WHERE id = $2", [netWeight, materialId]);

      return res.json({ success: true, id: transactionId });
    } catch (err) {
      console.error("Weighing Completion Error:", err);
      return res.status(500).json({ error: "Failed to complete weighing transaction" });
    }
  });

  // Reports
  app.get("/api/reports", authMiddleware, async (req: any, res) => {
    try {
      // Aggregate reports from batch records, audit logs, and deviations
      const batches = await query(`
        SELECT id, 'Batch Record' as type, 'Production' as category, 'Batch Summary ' || product_name || ' ' || batch_number as title, 
               product_name as product, batch_number as batchNumber, 'Final' as status, created_at as createdAt, 1 as version
        FROM batch_records 
        WHERE company_id = $1 AND status = 'Completed'
      `, [req.companyId]);

      const deviations = await query(`
        SELECT id, 'Deviation' as type, 'Quality' as category, 'Deviation Report - ' || description as title, 
               batch_id as batchNumber, 'Final' as status, created_at as createdAt, 1 as version
        FROM deviations 
        WHERE company_id = $1 AND status = 'Closed'
      `, [req.companyId]);

      const auditReports = [
        { id: 'R-AUDIT-01', type: 'Audit Trail', category: 'Compliance', title: 'Monthly Audit Log - March 2026', operator: 'System Administrator', status: 'Final', createdAt: new Date().toISOString(), tags: ['Audit', '21CFR'], version: 1 }
      ];

      const allReports = [
        ...batches.rows.map(b => ({ ...b, id: `R-BATCH-${b.id}`, operator: 'Production System', tags: ['Batch', 'GMP'] })),
        ...deviations.rows.map(d => ({ ...d, id: `R-DEV-${d.id}`, operator: 'QA System', tags: ['Quality', 'Deviation'] })),
        ...auditReports
      ];

      res.json(allReports);
    } catch (err) {
      res.status(500).json({ error: "Failed to fetch reports" });
    }
  });

  // Supply Chain
  app.get("/api/warehouses", authMiddleware, async (req: any, res) => {
    try {
      const warehouses = await query("SELECT * FROM warehouses WHERE company_id = $1", [req.companyId]);
      const bins = await query("SELECT b.* FROM bins b JOIN warehouses w ON b.warehouse_id = w.id WHERE w.company_id = $1", [req.companyId]);
      res.json(warehouses.rows.map(w => ({
        ...w,
        bins: bins.rows.filter(b => b.warehouse_id === w.id)
      })));
    } catch (err) {
      res.status(500).json({ error: "Failed to fetch warehouses" });
    }
  });

  app.get("/api/boms", authMiddleware, async (req: any, res) => {
    try {
      const boms = await query(`
        SELECT b.*, p.name as product_name 
        FROM boms b 
        JOIN products p ON b.product_id = p.id 
        WHERE b.company_id = $1
      `, [req.companyId]);
      const items = await query(`
        SELECT bi.*, m.name as material_name 
        FROM bom_items bi 
        JOIN boms b ON bi.bom_id = b.id 
        JOIN materials m ON bi.material_id = m.id 
        WHERE b.company_id = $1
      `, [req.companyId]);
      res.json(boms.rows.map(b => ({
        ...b,
        items: items.rows.filter(i => i.bom_id === b.id)
      })));
    } catch (err) {
      res.status(500).json({ error: "Failed to fetch BOMs" });
    }
  });

  app.get("/api/purchase-orders", authMiddleware, async (req: any, res) => {
    try {
      const pos = await query("SELECT * FROM purchase_orders WHERE company_id = $1", [req.companyId]);
      res.json(pos.rows);
    } catch (err) {
      res.status(500).json({ error: "Failed to fetch purchase orders" });
    }
  });

  app.get("/api/shipments", authMiddleware, async (req: any, res) => {
    try {
      const shipments = await query("SELECT * FROM shipments WHERE company_id = $1", [req.companyId]);
      res.json(shipments.rows);
    } catch (err) {
      res.status(500).json({ error: "Failed to fetch shipments" });
    }
  });

  app.get("/api/scheduling", authMiddleware, async (req: any, res) => {
    try {
      const batches = await query("SELECT * FROM batch_records WHERE company_id = $1", [req.companyId]);
      res.json(batches.rows.map(b => ({
        id: b.id,
        title: `Batch ${b.batch_number} - ${b.product_name}`,
        start: b.created_at,
        end: new Date(new Date(b.created_at).getTime() + 8 * 3600000).toISOString(), // 8 hours later
        type: 'Production',
        status: b.status
      })));
    } catch (err) {
      res.status(500).json({ error: "Failed to fetch scheduling" });
    }
  });

  // Quality & QC
  app.get("/api/inspections", authMiddleware, async (req: any, res) => {
    try {
      const inspections = await query("SELECT * FROM inspections WHERE company_id = $1", [req.companyId]);
      res.json(inspections.rows);
    } catch (err) {
      res.status(500).json({ error: "Failed to fetch inspections" });
    }
  });

  app.get("/api/maintenance", authMiddleware, async (req: any, res) => {
    try {
      const logs = await query(`
        SELECT ml.*, e.name as equipment_name 
        FROM maintenance_logs ml 
        JOIN equipment e ON ml.equipment_id = e.id 
        WHERE ml.company_id = $1
      `, [req.companyId]);
      res.json(logs.rows);
    } catch (err) {
      res.status(500).json({ error: "Failed to fetch maintenance logs" });
    }
  });

  app.get("/api/deviations", authMiddleware, async (req: any, res) => {
    try {
      const deviations = await query(`
        SELECT d.*, u.name as reported_by, 
        CASE 
          WHEN d.description LIKE '%temperature%' THEN 'Critical'
          WHEN d.description LIKE '%spill%' THEN 'Major'
          ELSE 'Minor'
        END as severity,
        'DEV-' || d.id as title,
        (SELECT id FROM capas WHERE deviation_id = d.id LIMIT 1) as capa_id
        FROM deviations d
        LEFT JOIN users u ON d.qa_approver_id = u.id
        WHERE d.company_id = $1
        ORDER BY d.created_at DESC
      `, [req.companyId]);
      res.json(deviations.rows);
    } catch (err) {
      res.status(500).json({ error: "Failed to fetch deviations" });
    }
  });

  // Permissions
  app.get("/api/permissions", authMiddleware, async (req: Request & { companyId?: number }, res: Response) => {
    try {
      const rolesRes = await query("SELECT DISTINCT role, permissions FROM users WHERE company_id = $1", [req.companyId]);
      const permissions = rolesRes.rows.map(row => ({
        role: row.role,
        ...safeJsonParse(row.permissions)
      }));
      return res.json(permissions);
    } catch (err) {
      return res.status(500).json({ error: "Failed to fetch permissions" });
    }
  });

  app.post("/api/permissions", authMiddleware, async (req: any, res) => {
    const { role, ...perms } = req.body;
    // In a real app, we'd update all users with this role or a role_permissions table
    await query("UPDATE users SET permissions = $1 WHERE role = $2 AND company_id = $3", [JSON.stringify(perms), role, req.companyId]);
    res.json({ success: true });
  });

  // Password Reset
  const requestResetSchema = z.object({
    email: z.string().email().optional(),
    phone: z.string().optional()
  }).refine(data => data.email || data.phone, {
    message: "Either email or phone must be provided"
  });

  app.post("/api/auth/request-reset", async (req, res) => {
    try {
      const { email, phone } = requestResetSchema.parse(req.body);
      
      // Check if user exists
      const userRes = await query("SELECT id FROM users WHERE email = $1 OR phone = $2", [email, phone]);
      if (userRes.rows.length === 0) {
        // Silent fail for security
        return res.json({ success: true, message: "If an account exists, an OTP has been sent." });
      }

      // Generate 6-digit OTP
      const otp = Math.floor(100000 + Math.random() * 900000).toString();
      const expiresAt = new Date(Date.now() + 15 * 60 * 1000); // 15 mins

      await query(`
        INSERT INTO password_resets (email, phone, otp, expires_at)
        VALUES ($1, $2, $3, $4)
        RETURNING id
      `, [email, phone, otp, expiresAt.toISOString()]);

      // In a real app, send email/SMS here
      console.log(`[SECURITY] Password reset OTP for ${email || phone}: ${otp}`);

      return res.json({ success: true, message: "OTP sent successfully" });
    } catch (err) {
      console.error("Password Reset Request Error:", err);
      return res.status(400).json({ error: "Invalid request" });
    }
  });

  const confirmResetSchema = z.object({
    email: z.string().email().optional(),
    phone: z.string().optional(),
    otp: z.string().length(6),
    newPassword: z.string().min(8)
  });

  app.post("/api/auth/confirm-reset", async (req, res) => {
    try {
      const { email, phone, otp, newPassword } = confirmResetSchema.parse(req.body);
      
      // Verify OTP
      const resetRes = await query(`
        SELECT * FROM password_resets 
        WHERE (email = $1 OR phone = $2) AND otp = $3 AND expires_at > CURRENT_TIMESTAMP
        ORDER BY created_at DESC LIMIT 1
      `, [email, phone, otp]);

      if (resetRes.rows.length === 0) {
        return res.status(400).json({ error: "Invalid or expired OTP" });
      }

      const hashed = await bcrypt.hash(newPassword, 10);
      await query("UPDATE users SET password_hash = $1 WHERE email = $2 OR phone = $3", [hashed, email, phone]);
      
      // Clean up used OTPs
      await query("DELETE FROM password_resets WHERE email = $1 OR phone = $2", [email, phone]);

      res.json({ success: true });
    } catch (err) {
      res.status(400).json({ error: "Invalid request" });
    }
  });

  // --- Vite Integration ---
  if (process.env.NODE_ENV !== "production") {
    const vite = await createViteServer({
      server: { middlewareMode: true },
      appType: "spa",
    });
    app.use(vite.middlewares);
  } else {
    app.use(express.static(path.join(__dirname, "dist")));
    app.get("*", (req, res) => res.sendFile(path.join(__dirname, "dist", "index.html")));
  }

  const PORT = Number(process.env.PORT) || 3000;
  httpServer.listen(PORT, "0.0.0.0", () => {
    console.log(`PharmaFlow SaaS Server running on http://localhost:${PORT}`);
  });
}

startServer().catch(err => {
  console.error("Failed to start server:", err);
});
