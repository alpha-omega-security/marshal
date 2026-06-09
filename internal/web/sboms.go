package web

import (
	"context"
	"fmt"
	"io"
	"log"
	"net/http"
	"path/filepath"
	"strconv"
	"time"

	"github.com/alpha-omega-security/marshal/internal/db"
	enrichpkgs "github.com/alpha-omega-security/marshal/internal/enrich/packages"
	"github.com/alpha-omega-security/marshal/internal/ingest"
)

type sbomsView struct {
	Theme         string
	Nav           string
	FilterInput   string
	CannedFilters []cannedFilterView // empty; layout only renders these under packages
	Imports       []sbomRow
	Flash         string
	FlashErr      string
}

type sbomRow struct {
	ID               uint
	Path             string
	Base             string
	Format           string
	SpecVersion      string
	Subject          string
	PackageCount     int
	LoadedAt         string
	EnrichmentStatus string
	EnrichmentError  string
	EnrichmentTook   string // friendly duration like "3m" when done
}

func (s *Server) sboms(w http.ResponseWriter, r *http.Request) {
	var imports []db.Import
	if err := s.g.Order("loaded_at desc").Find(&imports).Error; err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	rows := make([]sbomRow, len(imports))
	for i, im := range imports {
		took := ""
		if im.EnrichmentStartedAt != nil && im.EnrichmentFinishedAt != nil {
			d := im.EnrichmentFinishedAt.Sub(*im.EnrichmentStartedAt)
			took = d.Round(time.Second).String()
		}
		rows[i] = sbomRow{
			ID:               im.ID,
			Path:             im.Path,
			Base:             filepath.Base(im.Path),
			Format:           im.Format,
			SpecVersion:      im.SpecVersion,
			Subject:          im.Subject,
			PackageCount:     im.PackageCount,
			LoadedAt:         im.LoadedAt.Format("2006-01-02 15:04"),
			EnrichmentStatus: im.EnrichmentStatus,
			EnrichmentError:  im.EnrichmentError,
			EnrichmentTook:   took,
		}
	}
	view := sbomsView{
		Theme:    "marshal",
		Nav:      "sboms",
		Imports:  rows,
		Flash:    r.URL.Query().Get("flash"),
		FlashErr: r.URL.Query().Get("err"),
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	if err := s.tpl.ExecuteTemplate(w, "sboms.html", view); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
	}
}

func (s *Server) sbomsAdd(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Redirect(w, r, "/sboms", http.StatusSeeOther)
		return
	}
	// cap the multipart body to MaxInputBytes plus a small envelope budget;
	// the global withBodyLimit middleware skips /sboms/add so we set the
	// limit here, where it can reflect the SBOM input cap rather than the
	// 64 KiB form cap.
	r.Body = http.MaxBytesReader(w, r.Body, ingest.MaxInputBytes+(1<<20))
	if err := r.ParseMultipartForm(16 << 20); err != nil {
		http.Redirect(w, r, "/sboms?err="+escape(err.Error()), http.StatusSeeOther)
		return
	}
	file, header, err := r.FormFile("file")
	if err != nil {
		http.Redirect(w, r, "/sboms?err="+escape("file is required"), http.StatusSeeOther)
		return
	}
	defer func() { _ = file.Close() }()
	data, err := io.ReadAll(io.LimitReader(file, ingest.MaxInputBytes+1))
	if err != nil {
		http.Redirect(w, r, "/sboms?err="+escape(err.Error()), http.StatusSeeOther)
		return
	}
	if int64(len(data)) > ingest.MaxInputBytes {
		http.Redirect(w, r, "/sboms?err="+escape(fmt.Sprintf("file larger than %d bytes", ingest.MaxInputBytes)), http.StatusSeeOther)
		return
	}
	filename := filepath.Base(header.Filename)
	if filename == "" || filename == "." || filename == "/" {
		filename = "uploaded.sbom"
	}
	inserted, existing, err := ingest.LoadBytes(s.g, data, filename)
	if err != nil {
		http.Redirect(w, r, "/sboms?err="+escape(err.Error()), http.StatusSeeOther)
		return
	}

	// the import row was just inserted by LoadBytes; mark it pending so the
	// SBOMs page shows the right status badge before the goroutine starts.
	var imp db.Import
	if err := s.g.Order("id desc").First(&imp).Error; err == nil {
		s.g.Model(&imp).Updates(map[string]interface{}{"enrichment_status": "pending"})
		s.startAutoEnrich(imp.ID)
	}

	msg := fmt.Sprintf("loaded %s: %d new, %d already known. Enrichment is running in the background — refresh the SBOMs page to see status.", filename, inserted, existing)
	http.Redirect(w, r, "/sboms?flash="+escape(msg), http.StatusSeeOther)
}

// startAutoEnrich runs the packages enricher in a goroutine and writes
// status/timestamps/error back onto the Import row. Visible state means
// users can see whether enrichment is still running, finished, or errored.
func (s *Server) startAutoEnrich(importID uint) {
	go func() {
		ctx, cancel := context.WithTimeout(context.Background(), 30*time.Minute)
		defer cancel()

		now := time.Now()
		s.g.Model(&db.Import{}).Where("id = ?", importID).Updates(map[string]interface{}{
			"enrichment_status":     "running",
			"enrichment_started_at": &now,
		})

		_, err := enrichpkgs.Enrich(ctx, s.g, true, 7*24*time.Hour)

		fin := time.Now()
		update := map[string]interface{}{
			"enrichment_finished_at": &fin,
		}
		if err != nil {
			update["enrichment_status"] = "failed"
			update["enrichment_error"] = err.Error()
			log.Printf("upload auto-enrich (import %d): %v", importID, err)
		} else {
			update["enrichment_status"] = "done"
			update["enrichment_error"] = ""
		}
		s.g.Model(&db.Import{}).Where("id = ?", importID).Updates(update)
	}()
}

func (s *Server) sbomsDelete(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Redirect(w, r, "/sboms", http.StatusSeeOther)
		return
	}
	if err := r.ParseForm(); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	idStr := r.FormValue("id")
	id, err := strconv.ParseUint(idStr, 10, 64)
	if err != nil {
		http.Redirect(w, r, "/sboms?err="+escape("invalid id"), http.StatusSeeOther)
		return
	}
	if err := s.g.Delete(&db.Import{}, uint(id)).Error; err != nil {
		http.Redirect(w, r, "/sboms?err="+escape(err.Error()), http.StatusSeeOther)
		return
	}
	// Note: package rows are not removed. A package may have come from
	// multiple imports; we don't yet track that join, so removing the import
	// record only loses provenance, not the data. Document this in the UI.
	http.Redirect(w, r, "/sboms?flash="+escape("removed import (packages kept)"), http.StatusSeeOther)
}
