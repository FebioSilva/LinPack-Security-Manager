/**
 * Queries for fetching CVE and log data from a SPARQL endpoint.
 * These queries are used to retrieve information about vulnerabilities,
 */



/**
 * Query to get the highest severity CVEs affecting installed packages.
 * It retrieves the CVE ID, base score, severity, CVSS version, code,
 * package name, package version, and version intervals (min and max).
 * This query is used to identify the most critical vulnerabilities
 * in the system.
 */

export const highestSeverityCVEsQuery = `
PREFIX cve:     <http://purl.org/cyber/cve#>
PREFIX logs:    <http://www.semanticweb.org/logs-ontology-v2/>
PREFIX rdf:     <http://www.w3.org/1999/02/22-rdf-syntax-ns#>
PREFIX linpack: <http://www.semanticweb.org/linpack/>

SELECT DISTINCT
  ?cve
  ?base_score
  ?base_severity
  ?cvss_version
  ?cvss_code
  ?package_name
  ?package_version
   ?min ?max
WHERE {
  ?package a logs:Package ;
           logs:installed true ;
           logs:version              ?package_version ;
           logs:package_name ?package_name;
           linpack:has_related_product ?product .

  ?product a cve:Product ;
           cve:product_name ?product_name ;
           cve:has_version_interval ?version_interval .

  ?version_interval a cve:Versions ;
                    cve:has_cve_affecting_product ?cve ;
                    cve:has_product ?product .

  OPTIONAL { ?version_interval cve:min ?min . }
  OPTIONAL { ?version_interval cve:max ?max . }
  ?cve a cve:CVE ;
       cve:base_score ?base_score ;
       cve:base_severity ?base_severity ;
       cve:cvss_version ?cvss_version ;
       cve:cvss_code ?cvss_code .

}
ORDER BY DESC(?base_score)
`

/**
 * Query to count the number of CVEs per product.
 * It retrieves the version interval, minimum and maximum versions,
 * and the count of CVEs affecting each product.
 */
export const countCVEsPerProductQuery = `PREFIX cve:     <http://purl.org/cyber/cve#>
PREFIX linpack: <http://www.semanticweb.org/linpack/>
PREFIX logs:    <http://www.semanticweb.org/logs-ontology-v2/>
PREFIX rdf:     <http://www.w3.org/1999/02/22-rdf-syntax-ns#>

SELECT  ?version_interval ?min ?max (COUNT(DISTINCT ?cve) AS ?cve_count) ?product ?product_name ?package_name ?package_version
WHERE {
  ?package a logs:Package ;
           logs:package_name         ?package_name ;
           logs:version              ?package_version ;
           logs:installed true ;
           linpack:has_related_product ?product .

  ?product a cve:Product ;
           cve:product_name   ?product_name ;
           cve:has_version_interval ?version_interval .

  ?version_interval a cve:Versions ;
                    cve:has_cve_affecting_product ?cve .

  OPTIONAL { ?version_interval cve:min ?min . }
  OPTIONAL { ?version_interval cve:max ?max . }
}
GROUP BY ?version_interval ?min ?max ?product ?product_name ?package_name ?package_version
ORDER BY DESC(?cve_count)
`

/**
 * Query to fetch logs and CVEs for a specific year or all years.
 * It retrieves CVE details, affected products, vendors,
 * version intervals, packages, and related logs.
 * @param {string} [year] - The year to filter CVEs by publication date.
 * If not provided, retrieves all years.
 * @return {string} - The SPARQL query string.
*/
export const logsAndCVEs = (year) => `
PREFIX cve:     <http://purl.org/cyber/cve#>
PREFIX linpack: <http://www.semanticweb.org/linpack/>
PREFIX logs:    <http://www.semanticweb.org/logs-ontology-v2/>
PREFIX rdf:     <http://www.w3.org/1999/02/22-rdf-syntax-ns#>
PREFIX xsd:     <http://www.w3.org/2001/XMLSchema#>

SELECT DISTINCT
       ?cve ?description ?cvss_version ?base_score ?base_severity ?cvss_code ?pub_date

       ?product ?product_name
       ?vendor  ?vendor_name

       ?version_interval ?min ?max

       ?package  ?package_name ?package_version ?package_architecture
       ?log      ?event_type   ?timestamp ?action ?state ?decision ?command
WHERE {
  #######################################################################
  ## CVE                                                               ##
  #######################################################################
  ?cve  a                     cve:CVE ;
        cve:description       ?description ;
        cve:cvss_version      ?cvss_version ;
        cve:base_score        ?base_score ;
        cve:base_severity     ?base_severity ;
        cve:cvss_code         ?cvss_code ;
        cve:pub_date          ?pub_date ;
        cve:has_affected_product ?product ;
        cve:has_references ?reference .

  ${year ? `FILTER(STRSTARTS(STR(?pub_date), "${year}"))` : ""}

  #######################################################################
  ## Product + Vendor + affected versions                             ##
  #######################################################################
  ?product a                  cve:Product ;
           cve:product_name   ?product_name ;
           cve:has_vendor     ?vendor .

  ?vendor  a                  cve:Vendor ;
           cve:vendor_name    ?vendor_name .

  ?version_interval a cve:Versions ;
                    cve:has_product ?product ;
                    cve:has_cve_affecting_product ?cve .

  OPTIONAL { ?version_interval cve:min ?min . }
  OPTIONAL { ?version_interval cve:max ?max . }

  #######################################################################
  ## Package + Version Interval                                        ##
  #######################################################################
  ?package a logs:Package ;
           logs:package_name         ?package_name ;
           logs:version              ?package_version ;
           logs:package_architecture ?package_architecture ;
           logs:installed            True ;
           linpack:has_related_product ?product .


  #######################################################################
  ## Package + Version Interval                                        ##
  #######################################################################
  ?package a logs:Package ;
           logs:package_name         ?package_name ;
           logs:version              ?package_version ;
           logs:package_architecture ?package_architecture ;
           logs:installed            True ;
           linpack:has_related_product ?product .

  #######################################################################
  ## Related log events (optional)                                    ##
  #######################################################################
  OPTIONAL {
    ?log logs:has_package ?package ;
         rdf:type          ?event_type ;
         logs:timestamp_epoch    ?timestamp.
  }
  OPTIONAL { ?log logs:action ?action . }
  OPTIONAL { ?log logs:state ?state . }
  OPTIONAL { ?log logs:decision ?decision . }
  OPTIONAL { ?log logs:command ?command . }
}
`
/**
 * Generates a SPARQL query to fetch logs and CVEs for a specific year or all years.
 * @param {string} year - The year to filter CVEs by publication date.
 * If "all", retrieves all years.
 * @return {string} - The SPARQL query string.
 */

export function generateCVEQueryByYear(year) {
  console.log("Generating CVE query for year:", year);
  if (year === "all") {
    return logsAndCVEs(); 
  } else if (year && year.length === 4) {
    return logsAndCVEs(year);
  } else {
    throw new Error("Invalid year value");
  }
}

/**
 *      
 * 
 * Query to count new vulnerable logs since a given timestamp.
 * It retrieves the count of distinct logs that are associated with
 * installed packages, products, and version intervals
 * affected by CVEs.
 * @param {number} lastTimeStamp - The timestamp should be in epoch format (milliseconds since 1970-01-01T00:00:00Z).
 * This timestamp is used to filter logs that occurred after this time.
 * @return {string} - The SPARQL query string.
 */

export const countNewVulnerableLogsQuery = (lastTimeStamp) => `
PREFIX cve:     <http://purl.org/cyber/cve#>
PREFIX logs:    <http://www.semanticweb.org/logs-ontology-v2/>
PREFIX xsd:     <http://www.w3.org/2001/XMLSchema#>
PREFIX rdf:     <http://www.w3.org/1999/02/22-rdf-syntax-ns#>
PREFIX linpack: <http://www.semanticweb.org/linpack/>

SELECT (COUNT(DISTINCT ?log) AS ?logCount)
WHERE {
  ?package a logs:Package ;
           logs:installed true ;
           logs:package_name ?package_name ;
           linpack:has_related_product ?product .

  ?product a cve:Product ;
           cve:product_name ?product_name ;
           cve:has_version_interval ?vi .

  ?vi a cve:Versions ;
      cve:has_product ?product ;
      cve:has_cve_affecting_product ?cve .

  ?log logs:has_package ?package ;
       logs:timestamp_epoch ?timestamp .

  FILTER(?timestamp > ${lastTimeStamp})
}`