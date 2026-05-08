use base64::{engine::general_purpose as base64_engine, Engine as _};
use xml::writer::{EventWriter, XmlEvent as WriterEvent};

use crate::{
    crypt::ciphers::Cipher,
    db::{AutoType, AutoTypeAssociation, Entry, History, Value},
    xml_db::dump::{DumpXml, SimpleTag},
};

impl DumpXml for Entry {
    fn dump_xml<E: std::io::Write>(
        &self,
        writer: &mut EventWriter<E>,
        inner_cipher: &mut dyn Cipher,
    ) -> Result<(), xml::writer::Error> {
        writer.write(WriterEvent::start_element("Entry"))?;

        SimpleTag("UUID", &self.uuid).dump_xml(writer, inner_cipher)?;

        SimpleTag("Tags", &self.tags.join(";")).dump_xml(writer, inner_cipher)?;

        for (field_name, field_value) in &self.fields {
            writer.write(WriterEvent::start_element("String"))?;

            SimpleTag("Key", field_name).dump_xml(writer, inner_cipher)?;
            field_value.dump_xml(writer, inner_cipher)?;

            writer.write(WriterEvent::end_element())?; // String
        }

        // Per-entry binary attachment references. The actual bytes live in the
        // KDBX4 inner-header pool (or KDBX3 meta `<Binaries>`); here we just
        // emit `<Binary><Key>name</Key><Value Ref="N"/></Binary>` so KeePassXC
        // can resolve them.
        for (key, identifier) in &self.binaries {
            writer.write(WriterEvent::start_element("Binary"))?;

            SimpleTag("Key", key).dump_xml(writer, inner_cipher)?;

            writer.write(WriterEvent::start_element("Value").attr("Ref", identifier))?;
            writer.write(WriterEvent::end_element())?; // Value

            writer.write(WriterEvent::end_element())?; // Binary
        }

        self.custom_data.dump_xml(writer, inner_cipher)?;

        if let Some(ref value) = self.autotype {
            value.dump_xml(writer, inner_cipher)?;
        }

        self.times.dump_xml(writer, inner_cipher)?;

        if let Some(value) = self.icon_id {
            SimpleTag("IconID", value).dump_xml(writer, inner_cipher)?;
        }

        if let Some(ref value) = self.custom_icon_uuid {
            SimpleTag("CustomIconUUID", value).dump_xml(writer, inner_cipher)?;
        }

        if let Some(ref value) = self.foreground_color {
            SimpleTag("ForegroundColor", value).dump_xml(writer, inner_cipher)?;
        }

        if let Some(ref value) = self.background_color {
            SimpleTag("BackgroundColor", value).dump_xml(writer, inner_cipher)?;
        }

        if let Some(ref value) = self.override_url {
            SimpleTag("OverrideURL", value).dump_xml(writer, inner_cipher)?;
        }

        if let Some(value) = self.quality_check {
            SimpleTag("QualityCheck", value).dump_xml(writer, inner_cipher)?;
        }

        if let Some(ref value) = self.history {
            value.dump_xml(writer, inner_cipher)?;
        }

        writer.write(WriterEvent::end_element())?; // Entry

        Ok(())
    }
}

impl DumpXml for Value {
    fn dump_xml<E: std::io::Write>(
        &self,
        writer: &mut EventWriter<E>,
        inner_cipher: &mut dyn Cipher,
    ) -> Result<(), xml::writer::Error> {
        match self {
            Value::Bytes(b) => {
                // The previous implementation called `.expect("utf-8")` and
                // mangled non-UTF-8 input. That's a soundness hazard when a
                // caller stuffs raw bytes into a `Value::Bytes` field. Fall
                // back to UTF-8 when the bytes happen to be valid (preserves
                // the historical wire shape for round-trips) and to base64
                // otherwise.
                match std::str::from_utf8(b) {
                    Ok(s) => SimpleTag("Value", s).dump_xml(writer, inner_cipher),
                    Err(_) => {
                        let encoded = base64_engine::STANDARD.encode(b);
                        SimpleTag("Value", &encoded).dump_xml(writer, inner_cipher)
                    }
                }
            }
            Value::Unprotected(s) => SimpleTag("Value", s).dump_xml(writer, inner_cipher),
            Value::Protected(p) => {
                writer.write(WriterEvent::start_element("Value").attr("Protected", "True"))?;

                let encrypted_value = inner_cipher
                    .encrypt(p.unsecure())
                    .expect("Encrypt with inner cipher");

                let protected_value = base64_engine::STANDARD.encode(&encrypted_value);

                writer.write(WriterEvent::characters(&protected_value))?;

                writer.write(WriterEvent::end_element())?;
                Ok(())
            }
        }
    }
}

impl DumpXml for AutoType {
    fn dump_xml<E: std::io::Write>(
        &self,
        writer: &mut EventWriter<E>,
        inner_cipher: &mut dyn Cipher,
    ) -> Result<(), xml::writer::Error> {
        writer.write(WriterEvent::start_element("AutoType"))?;

        SimpleTag("Enabled", self.enabled).dump_xml(writer, inner_cipher)?;

        if let Some(ref value) = self.sequence {
            SimpleTag("DefaultSequence", value).dump_xml(writer, inner_cipher)?;
        }

        for assoc in &self.associations {
            assoc.dump_xml(writer, inner_cipher)?;
        }

        writer.write(WriterEvent::end_element())?;
        Ok(())
    }
}

impl DumpXml for AutoTypeAssociation {
    fn dump_xml<E: std::io::Write>(
        &self,
        writer: &mut EventWriter<E>,
        inner_cipher: &mut dyn Cipher,
    ) -> Result<(), xml::writer::Error> {
        writer.write(WriterEvent::start_element("Association"))?;

        if let Some(ref value) = self.window {
            SimpleTag("Window", value).dump_xml(writer, inner_cipher)?;
        }

        if let Some(ref value) = self.sequence {
            SimpleTag("KeystrokeSequence", value).dump_xml(writer, inner_cipher)?;
        }

        writer.write(WriterEvent::end_element())?;
        Ok(())
    }
}

impl DumpXml for History {
    fn dump_xml<E: std::io::Write>(
        &self,
        writer: &mut EventWriter<E>,
        inner_cipher: &mut dyn Cipher,
    ) -> Result<(), xml::writer::Error> {
        writer.write(WriterEvent::start_element("History"))?;

        for entry in &self.entries {
            entry.dump_xml(writer, inner_cipher)?;
        }

        writer.write(WriterEvent::end_element())?;
        Ok(())
    }
}
