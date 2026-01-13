package api

import (
	"net/http"
	"strconv"

	"github.com/banking/audit-compliance/internal/domain"
	"github.com/banking/audit-compliance/internal/service"
	"github.com/google/uuid"
	"github.com/labstack/echo/v4"
)

type AuditHandler struct {
	auditService *service.AuditService
}

func NewAuditHandler(auditService *service.AuditService) *AuditHandler {
	return &AuditHandler{
		auditService: auditService,
	}
}

// GetAuditTrail handles GET /audit/transactions/:transaction_id
func (h *AuditHandler) GetAuditTrail(c echo.Context) error {
	txIDStr := c.Param("transaction_id")
	txID, err := uuid.Parse(txIDStr)
	if err != nil {
		return c.JSON(http.StatusBadRequest, map[string]string{"error": "invalid transaction_id"})
	}

	filter := domain.AuditEventFilter{
		TransactionID: &txID,
		Limit:         100, // Defualt limit
	}

	page, err := h.auditService.GetAuditTrail(c.Request().Context(), filter)
	if err != nil {
		return c.JSON(http.StatusInternalServerError, map[string]string{"error": "failed to retrieve audit trail"})
	}

	return c.JSON(http.StatusOK, page)
}

// SearchEvents handles GET /audit/search
func (h *AuditHandler) SearchEvents(c echo.Context) error {
	query := c.QueryParam("q")
	if query == "" {
		return c.JSON(http.StatusBadRequest, map[string]string{"error": "missing query parameter 'q'"})
	}

	from, _ := strconv.Atoi(c.QueryParam("from"))
	size, _ := strconv.Atoi(c.QueryParam("size"))
	if size == 0 {
		size = 20
	}

	page, err := h.auditService.SearchEvents(c.Request().Context(), query, from, size)
	if err != nil {
		return c.JSON(http.StatusInternalServerError, map[string]string{"error": "search failed"})
	}

	return c.JSON(http.StatusOK, page)
}

// RegisterRoutes registers the API routes
func (h *AuditHandler) RegisterRoutes(e *echo.Group) {
	e.GET("/transactions/:transaction_id", h.GetAuditTrail)
	e.GET("/search", h.SearchEvents)
}
