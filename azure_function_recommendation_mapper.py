
import azure.functions as func
import json
import logging
from difflib import SequenceMatcher

def main(req: func.HttpRequest) -> func.HttpResponse:
    """
    Azure Function to map Excel recommendation names to Azure API recommendationTypeIds

    Input JSON structure:
    {
        "excelNames": ["recommendation name 1", "recommendation name 2", ...],
        "apiRecommendations": [Azure API response with recommendations array]
    }

    Output JSON structure:
    [
        {
            "recommendationName": "original name from Excel",
            "recommendationTypeId": "matched typeId from API",
            "matchScore": 0.95,
            "apiSolution": "matched solution name from API"
        }
    ]
    """

    logging.info('Processing recommendation mapping request')

    try:
        # Get input data from Logic App request
        req_body = req.get_json()
        excel_names = req_body.get('excelNames', [])
        api_recommendations = req_body.get('apiRecommendations', [])

        logging.info(f'Processing {len(excel_names)} Excel names against {len(api_recommendations)} API recommendations')

        # Create mapping between names and typeIds
        result_mapping = []

        # Process each Excel recommendation name
        for excel_name in excel_names:
            best_match = None
            best_score = 0

            # Clean the Excel name for better matching
            clean_excel_name = excel_name.strip().lower()

            # Search for the best match in API recommendations
            for recommendation in api_recommendations:
                # Extract solution name from API response
                api_solution = recommendation.get('properties', {}).get('shortDescription', {}).get('solution', '')
                clean_api_solution = api_solution.strip().lower()

                # Try exact match first (most reliable)
                if clean_excel_name == clean_api_solution:
                    best_match = recommendation
                    best_score = 1.0
                    logging.info(f'Exact match found for: {excel_name}')
                    break

                # Try fuzzy matching with similarity score
                similarity = SequenceMatcher(None, clean_excel_name, clean_api_solution).ratio()

                # Update best match if this similarity is higher
                if similarity > best_score and similarity > 0.8:  # 80% similarity threshold
                    best_match = recommendation
                    best_score = similarity

            # Add result to mapping array
            if best_match:
                result_mapping.append({
                    "recommendationName": excel_name,
                    "recommendationTypeId": best_match.get('properties', {}).get('recommendationTypeId', ''),
                    "matchScore": round(best_score, 2),
                    "apiSolution": best_match.get('properties', {}).get('shortDescription', {}).get('solution', ''),
                    "status": "MATCHED"
                })
                logging.info(f'Match found for "{excel_name}" with score {best_score:.2f}')
            else:
                # No match found - add empty entry for debugging
                result_mapping.append({
                    "recommendationName": excel_name,
                    "recommendationTypeId": "",
                    "matchScore": 0,
                    "apiSolution": "NO MATCH FOUND",
                    "status": "NOT_MATCHED"
                })
                logging.warning(f'No match found for: {excel_name}')

        # Log summary
        matched_count = len([r for r in result_mapping if r['status'] == 'MATCHED'])
        logging.info(f'Mapping completed: {matched_count}/{len(excel_names)} recommendations matched')

        # Return successful response
        return func.HttpResponse(
            json.dumps(result_mapping, ensure_ascii=False),
            status_code=200,
            headers={"Content-Type": "application/json; charset=utf-8"}
        )

    except ValueError as ve:
        # Handle JSON parsing errors
        error_msg = f"Invalid JSON input: {str(ve)}"
        logging.error(error_msg)
        return func.HttpResponse(
            json.dumps({"error": error_msg, "type": "JSON_ERROR"}),
            status_code=400,
            headers={"Content-Type": "application/json"}
        )

    except KeyError as ke:
        # Handle missing required fields
        error_msg = f"Missing required field: {str(ke)}"
        logging.error(error_msg)
        return func.HttpResponse(
            json.dumps({"error": error_msg, "type": "MISSING_FIELD"}),
            status_code=400,
            headers={"Content-Type": "application/json"}
        )

    except Exception as e:
        # Handle any other unexpected errors
        error_msg = f"Unexpected error: {str(e)}"
        logging.error(error_msg)
        return func.HttpResponse(
            json.dumps({"error": error_msg, "type": "GENERAL_ERROR"}),
            status_code=500,
            headers={"Content-Type": "application/json"}
        )
