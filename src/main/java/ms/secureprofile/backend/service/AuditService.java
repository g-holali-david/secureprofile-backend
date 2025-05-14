package ms.secureprofile.backend.service;

import jakarta.servlet.http.HttpServletRequest;
import ms.secureprofile.backend.model.AuditLog;
import ms.secureprofile.backend.repository.AuditLogRepository;
import org.springframework.stereotype.Service;

@Service
public class AuditService {
    private final AuditLogRepository auditLogRepository;

    public AuditService(AuditLogRepository repo) {
        this.auditLogRepository = repo;
    }

    public void log(String username, String action, String ipAddress) {
        auditLogRepository.save(new AuditLog(username, action, ipAddress));
    }
}