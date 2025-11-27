-- ============================================================================
-- NGFW Database Schema
-- جميع ملفات SQL المدمجة في ملف واحد
-- ============================================================================

-- ============================================================================
-- 1. إصلاح Schema الأساسي (fix_schema.sql)
-- ============================================================================

-- نفّذ هذا على قاعدة ngfw_db
-- 1) إعادة تسمية dst_port -> dest_port إذا موجود
DO $$
BEGIN
  IF EXISTS (
      SELECT 1 FROM information_schema.columns
      WHERE table_name='network_flows' AND column_name='dst_port'
  ) THEN
    ALTER TABLE network_flows RENAME COLUMN dst_port TO dest_port;
  END IF;
END$$;

-- 2) تأكد من وجود عمود dest_port (إن لم يكن موجود أضفه)
DO $$
BEGIN
  IF NOT EXISTS (
      SELECT 1 FROM information_schema.columns
      WHERE table_name='network_flows' AND column_name='dest_port'
  ) THEN
    ALTER TABLE network_flows ADD COLUMN dest_port integer DEFAULT 0;
  END IF;
END$$;

-- 3) تأكد من وجود عمود timestamp (مناسب لتخزين وقت الالتقاط)
DO $$
BEGIN
  IF NOT EXISTS (
      SELECT 1 FROM information_schema.columns
      WHERE table_name='network_flows' AND column_name='timestamp'
  ) THEN
    ALTER TABLE network_flows ADD COLUMN timestamp timestamptz DEFAULT now();
  END IF;
END$$;

-- 4) أعمدة ML: ml_label و ml_score
DO $$
BEGIN
  IF NOT EXISTS (
      SELECT 1 FROM information_schema.columns
      WHERE table_name='network_flows' AND column_name='ml_label'
  ) THEN
    ALTER TABLE network_flows ADD COLUMN ml_label smallint NULL;
  END IF;

  IF NOT EXISTS (
      SELECT 1 FROM information_schema.columns
      WHERE table_name='network_flows' AND column_name='ml_score'
  ) THEN
    ALTER TABLE network_flows ADD COLUMN ml_score double precision NULL;
  END IF;
END$$;

-- 5) إذا جدول network_flows غير موجود نهائيًا: (تعريف مقترح)
CREATE TABLE IF NOT EXISTS network_flows (
  id serial PRIMARY KEY,
  src_ip text,
  dest_ip text,
  src_port integer,
  dest_port integer,
  protocol text,
  timestamp timestamptz DEFAULT now(),
  -- هنا تضع الأعمدة اللي الموديل يحتاجها (مثال مبسّط)
  tot_fwd_pkts integer DEFAULT 0,
  tot_bwd_pkts integer DEFAULT 0,
  totlen_fwd_pkts integer DEFAULT 0,
  totlen_bwd_pkts integer DEFAULT 0,
  flow_duration double precision DEFAULT 0,
  pkt_hash text,
  -- أعمدة ML
  ml_label smallint NULL,
  ml_score double precision NULL
);

-- 6) جدول network_events (المكان اللي sniffer يعمل عليه FK)
CREATE TABLE IF NOT EXISTS network_events (
  id serial PRIMARY KEY,
  flow_id integer REFERENCES network_flows(id) ON DELETE CASCADE,
  src_ip text,
  dest_ip text,
  src_port integer,
  dest_port integer,
  protocol text,
  timestamp timestamptz DEFAULT now(),
  created_at timestamptz DEFAULT now()
);

-- 7) جدول ml_predictions (يرتبط ب network_events)
CREATE TABLE IF NOT EXISTS ml_predictions (
  id serial PRIMARY KEY,
  event_id integer REFERENCES network_events(id) ON DELETE CASCADE,
  ml_label smallint NOT NULL,
  ml_score double precision,
  model_version text,
  created_at timestamptz DEFAULT now()
);

-- 8) فهارس لمساعدة الاستعلامات
CREATE INDEX IF NOT EXISTS idx_network_flows_ts ON network_flows(timestamp);
CREATE INDEX IF NOT EXISTS idx_network_flows_srcip ON network_flows(src_ip);
CREATE INDEX IF NOT EXISTS idx_network_events_ts ON network_events(timestamp);

-- ============================================================================
-- 2. إصلاح Schema v3 (fix_schema_v3.sql)
-- ============================================================================

-- 🧠 تأكيد على أن الأعمدة موجودة بالنوع الصحيح

DO $$
BEGIN
    -- تأكد من أن العمود protocol موجود ومكتوب كنص
    IF EXISTS (
        SELECT 1 FROM information_schema.columns
        WHERE table_name = 'network_flows' AND column_name = 'protocol'
    ) THEN
        EXECUTE 'ALTER TABLE network_flows ALTER COLUMN protocol TYPE TEXT USING protocol::TEXT';
    ELSE
        EXECUTE 'ALTER TABLE network_flows ADD COLUMN protocol TEXT';
    END IF;

    -- تأكد من وجود العمود pkt_hash
    IF NOT EXISTS (
        SELECT 1 FROM information_schema.columns
        WHERE table_name = 'network_flows' AND column_name = 'pkt_hash'
    ) THEN
        EXECUTE 'ALTER TABLE network_flows ADD COLUMN pkt_hash TEXT';
    END IF;
END $$;

-- ============================================================================
-- 3. جداول إضافية للـ IPS و Signatures
-- ============================================================================

-- جدول blocked_ips
CREATE TABLE IF NOT EXISTS blocked_ips (
  id serial PRIMARY KEY,
  ip text NOT NULL UNIQUE,
  blocked_at timestamptz DEFAULT now(),
  blocked_until timestamptz,
  reason text,
  created_at timestamptz DEFAULT now()
);

CREATE INDEX IF NOT EXISTS idx_blocked_ips_ip ON blocked_ips(ip);
CREATE INDEX IF NOT EXISTS idx_blocked_ips_until ON blocked_ips(blocked_until);

-- جدول signatures
CREATE TABLE IF NOT EXISTS signatures (
  id serial PRIMARY KEY,
  name text NOT NULL,
  pattern text NOT NULL,
  severity text NOT NULL CHECK (severity IN ('low', 'medium', 'high', 'critical')),
  enabled boolean DEFAULT true,
  created_at timestamptz DEFAULT now(),
  updated_at timestamptz DEFAULT now()
);

CREATE INDEX IF NOT EXISTS idx_signatures_enabled ON signatures(enabled);
CREATE INDEX IF NOT EXISTS idx_signatures_severity ON signatures(severity);

-- جدول signature_matches
CREATE TABLE IF NOT EXISTS signature_matches (
  id serial PRIMARY KEY,
  event_id integer REFERENCES network_events(id) ON DELETE CASCADE,
  signature_id integer REFERENCES signatures(id) ON DELETE CASCADE,
  matched_at timestamptz DEFAULT now()
);

CREATE INDEX IF NOT EXISTS idx_signature_matches_event ON signature_matches(event_id);
CREATE INDEX IF NOT EXISTS idx_signature_matches_signature ON signature_matches(signature_id);

-- ============================================================================
-- 4. جدول url_checks (لحفظ نتائج فحص URLs للتعلم الذاتي)
-- ============================================================================

CREATE TABLE IF NOT EXISTS url_checks (
  id serial PRIMARY KEY,
  url text NOT NULL,
  is_safe boolean NOT NULL,
  is_blocked boolean NOT NULL DEFAULT false,
  ml_score double precision,
  ml_label text,
  ml_threshold double precision,
  ml_confidence double precision,
  url_validation jsonb,
  threat_indicators jsonb,
  signatures jsonb,
  ips_decision jsonb,
  checked_at timestamptz DEFAULT now(),
  created_at timestamptz DEFAULT now()
);

CREATE INDEX IF NOT EXISTS idx_url_checks_url ON url_checks(url);
CREATE INDEX IF NOT EXISTS idx_url_checks_is_blocked ON url_checks(is_blocked);
CREATE INDEX IF NOT EXISTS idx_url_checks_checked_at ON url_checks(checked_at);
CREATE INDEX IF NOT EXISTS idx_url_checks_is_safe ON url_checks(is_safe);

-- ============================================================================
-- ملاحظات:
-- ============================================================================
-- 1. نفّذ هذا الملف على قاعدة ngfw_db
-- 2. يمكن تنفيذ الأقسام بشكل منفصل حسب الحاجة
-- 3. جميع الأوامر آمنة (IF EXISTS / IF NOT EXISTS)
-- 4. جدول url_checks يساعد في التعلم الذاتي للموديل
-- ============================================================================


